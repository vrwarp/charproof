import {
  encrypt,
  encryptPayload,
  decrypt,
  decryptPayload,
  exportDevicePrivateKey,
  exportDevicePublicKey,
  exportSymmetricKey,
  generateDeviceKeyPair,
  generateSymmetricKey,
  base64UrlToUint8,
  getCrypto,
  importDevicePrivateKey,
  importDevicePublicKey,
  unwrapAmk,
  wrapAmk,
  decryptHybrid,
  blindLedgerId
} from "./core/crypto";
import {
  unwrapActiveAmk,
  unwrapAmkById,
  tryRecoverAmkWithPrfKey,
  prepareGenesisDocument,
  prepareRegistrationData,
  rotateKeys,
  preparePendingDeviceRequest,
  preparePendingDeviceApproval
} from "./core/deviceLogic";
import type {
  AccountKeysDocument,
  PendingDevice,
  DevicePublicKey,
  RecoveryMethod,
  LedgerCredentials,
  KeystoreEntry,
  DecryptedKeystoreEntry
} from "./core/types";
import type { AesGcmKey, AccountKeyStore, LocalDeviceStore, AuthProvider, RawKeyBytes } from "./core/interfaces";

import { FirestoreAccountKeyStore } from "./browser/FirestoreAccountKeyStore";
import { BrowserLocalDeviceStore } from "./browser/BrowserLocalDeviceStore";
import { FirebaseAuthProvider } from "./browser/FirebaseAuthProvider";

import { derivePrfMasterKey } from "./prfService";

let store: AccountKeyStore = new FirestoreAccountKeyStore();
let local: LocalDeviceStore = new BrowserLocalDeviceStore();
let auth: AuthProvider = new FirebaseAuthProvider();

export function setDeviceServiceProviders(providers: {
  accountKeyStore?: AccountKeyStore;
  localDeviceStore?: LocalDeviceStore;
  authProvider?: AuthProvider;
}) {
  if (providers.accountKeyStore) store = providers.accountKeyStore;
  if (providers.localDeviceStore) local = providers.localDeviceStore;
  if (providers.authProvider) auth = providers.authProvider;
}

export function getDeviceId(): string {
  return local.getDeviceId();
}

export function getDeviceName(): string {
  return local.getDeviceName();
}

export function setDeviceName(name: string) {
  local.setDeviceName(name);
}

// === PRF HELPERS ===

async function getPrfMethodId(prfKey: AesGcmKey): Promise<string> {
  const rawKey = await getCrypto().exportSymmetricKey(prfKey);
  const hash = await getCrypto().digest("SHA-256", rawKey);
  const hashArray = Array.from(new Uint8Array(hash));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return `__recovery_prf_${hashHex.slice(0, 16)}`;
}

// === AMK LIFECYCLE CACHE ===

let cachedAmk: AesGcmKey | null = null;
let cachedAmkId: string | null = null;
let verificationPromise: Promise<{ amk: AesGcmKey, amkId: string }> | null = null;

export function clearAmkSessionCache() {
  cachedAmk = null;
  cachedAmkId = null;
  verificationPromise = null;
}

export async function getActiveAmk(): Promise<{ amk: AesGcmKey, amkId: string }> {
  if (cachedAmk && cachedAmkId) return { amk: cachedAmk, amkId: cachedAmkId };
  if (verificationPromise) return verificationPromise;

  verificationPromise = (async () => {
    try {
      const user = auth.getCurrentUser();
      if (!user || user.isAnonymous) {
        const err = new Error("Must be signed in to access AMK.");
        (err as any).retryable = false;
        throw err;
      }

      const deviceId = getDeviceId();
      const accountKeys = await store.getAccountKeys();

      if (!accountKeys) {
        // Genesis device setup
        const result = await setupGenesisDevice(user.uid);
        cachedAmk = result.amk;
        cachedAmkId = result.amkId;
        return result;
      }

      const deviceKeys = await local.loadDeviceKeys();
      const amkId = accountKeys.activeAmkId;
      const wrappedAmkBase64 = accountKeys.keyring[amkId]?.[deviceId];

      if (!wrappedAmkBase64 || !deviceKeys) {
        // Attempt PRF recovery
        const recovered = await tryRecoverAmkWithPrf(accountKeys);
        if (recovered) {
          console.log("Silent recovery successful. Auto-registering device...");
          await registerCurrentDevice(recovered.amk, recovered.amkId);
          cachedAmk = recovered.amk;
          cachedAmkId = recovered.amkId;
          return recovered;
        }

        if (!wrappedAmkBase64) {
          const err = new Error("UNRECOGNIZED_DEVICE: This browser instance has not been authorized to access your encrypted data.");
          (err as any).retryable = false;
          throw err;
        }
        const err = new Error("IDENTITY_MISMATCH: The passkey used does not match the one registered for this device.");
        (err as any).retryable = false;
        throw err;
      }

      const amkBuffer = await unwrapAmkById(accountKeys, deviceId, deviceKeys.privateKey, amkId);

      cachedAmk = await getCrypto().importSymmetricKey(new Uint8Array(amkBuffer) as RawKeyBytes);
      cachedAmkId = amkId;

      opportunisticallyEnableRecovery().catch(e => console.warn("Opportunistic recovery check failed:", e));

      return { amk: cachedAmk, amkId: cachedAmkId };
    } catch (e: any) {
      // Annotate network errors as retryable if not already set
      if (e.retryable === undefined) {
        const code = e.code || '';
        (e as any).retryable = ['unavailable', 'deadline-exceeded', 'resource-exhausted', 'aborted'].includes(code);
      }
      throw e;
    } finally {
      verificationPromise = null;
    }
  })();

  return verificationPromise;
}

export async function getAmkById(targetAmkId: string): Promise<AesGcmKey> {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) throw new Error("Must be signed in.");

  await getActiveAmk();

  const deviceId = getDeviceId();
  const accountKeys = await store.getAccountKeys();
  if (!accountKeys) throw new Error("Account keys missing.");

  const wrappedAmkBase64 = accountKeys.keyring[targetAmkId]?.[deviceId];
  if (!wrappedAmkBase64) {
    throw new Error(`AMK ${targetAmkId} not found or not wrapped for this device.`);
  }

  const deviceKeys = await local.loadDeviceKeys();
  if (!deviceKeys) throw new Error("Device keys missing.");

  const amkBuffer = await unwrapAmkById(accountKeys, deviceId, deviceKeys.privateKey, targetAmkId);

  return await getCrypto().importSymmetricKey(new Uint8Array(amkBuffer) as RawKeyBytes);
}

async function opportunisticallyEnableRecovery() {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) return;

  const { isCurrentPrfSealed } = await getRecoveryStatus();
  if (!isCurrentPrfSealed) {
    const cachedPrfKey = await local.loadMasterKey(user.uid);
    if (cachedPrfKey) {
      console.log("Current PRF key is available but not sealed for this AMK. Re-enabling...");
      await enablePrfRecovery();
    }
  }
}

export async function getRecoveryStatus(): Promise<{ 
  isSealed: boolean, 
  methods: string[], 
  isCurrentPrfSealed: boolean 
}> {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) return { isSealed: false, methods: [], isCurrentPrfSealed: false };

  const accountKeys = await store.getAccountKeys();
  if (!accountKeys) return { isSealed: false, methods: [], isCurrentPrfSealed: false };

  const amkId = accountKeys.activeAmkId;
  const keyring = accountKeys.keyring[amkId] || {};
  
  const registeredMethodIds = Object.keys(accountKeys.recoveryMethods || {});
  const activeMethodIds = registeredMethodIds.filter(id => !!keyring[id]);
  
  const methods: string[] = [];
  if (activeMethodIds.length > 0) {
    try {
      const { amk } = await getActiveAmk();
      for (const id of activeMethodIds) {
        try {
          const plainLabel = await decryptPayload(amk, accountKeys.recoveryMethods[id].encryptedLabel);
          methods.push(plainLabel);
        } catch (e) {
          methods.push(accountKeys.recoveryMethods[id].type === 'prf' ? "Passkey Recovery" : "Phrase Recovery");
        }
      }
    } catch (e) {
      activeMethodIds.forEach(id => {
        methods.push(accountKeys.recoveryMethods[id].type === 'prf' ? "Passkey Recovery" : "Phrase Recovery");
      });
    }
  }

  const cachedPrfKey = await local.loadMasterKey(user.uid);
  let isCurrentPrfSealed = false;
  if (cachedPrfKey) {
    const methodId = await getPrfMethodId(cachedPrfKey);
    isCurrentPrfSealed = !!keyring[methodId];
  }

  return {
    isSealed: activeMethodIds.length > 0,
    methods,
    isCurrentPrfSealed
  };
}

async function tryRecoverAmkWithPrf(data: AccountKeysDocument): Promise<{ amk: AesGcmKey, amkId: string } | null> {
  const prfMethods = (Object.values(data.recoveryMethods || {}) as RecoveryMethod[]).filter(
    (m: RecoveryMethod) => m.type === 'prf' && m.credentialId
  );
  const credentialIds = prfMethods.map(m => m.credentialId as string);
  if (credentialIds.length === 0) return null;

  try {
    const { masterKey, usedCredentialId } = await derivePrfMasterKey(credentialIds);
    const usedMethodId = await getPrfMethodId(masterKey);

    const recovered = await tryRecoverAmkWithPrfKey(data, masterKey, usedMethodId);
    if (!recovered) return null;

    const amk = await getCrypto().importSymmetricKey(new Uint8Array(recovered.amkRaw) as RawKeyBytes);

    return { amk, amkId: recovered.amkId };
  } catch (e) {
    console.warn("PRF Recovery failed:", e);
    return null;
  }
}

export async function registerCurrentDevice(amk: AesGcmKey, amkId: string): Promise<void> {
  const user = auth.getCurrentUser();
  if (!user) throw new Error("Must be signed in.");

  const deviceKeyPair = await generateDeviceKeyPair();
  const privB64 = await exportDevicePrivateKey(deviceKeyPair.privateKey);
  const pubB64 = await exportDevicePublicKey(deviceKeyPair.publicKey);

  // C3 FIX: Do NOT save keys to IndexedDB yet — defer until after Firestore confirms.
  // This prevents permanent lockout if the Firestore write fails.

  const deviceId = getDeviceId();
  const currentDoc = await store.getAccountKeys();
  if (!currentDoc) throw new Error("Account keys missing.");

  const updatedDoc = await prepareRegistrationData(
    amk,
    amkId,
    getDeviceName(),
    deviceId,
    pubB64,
    currentDoc
  );

  // Commit to Firestore first — if this throws, local keys remain unchanged.
  await store.setAccountKeys(updatedDoc);

  // Only persist the new keys locally after the remote write succeeds.
  await local.saveDeviceKeys({ privateKey: privB64, publicKey: pubB64 });

  cachedAmk = amk;
  cachedAmkId = amkId;
}

async function setupGenesisDevice(uid: string): Promise<{ amk: AesGcmKey, amkId: string }> {
  // C2 FIX: Reuse existing local device keys if present (idempotent genesis).
  // Prevents credential mismatch if a previous genesis attempt saved keys to IDB
  // but failed before committing to Firestore.
  let privB64: string;
  let pubB64: string;
  const existingKeys = await local.loadDeviceKeys();
  if (existingKeys) {
    privB64 = existingKeys.privateKey;
    pubB64 = existingKeys.publicKey;
  } else {
    const deviceKeyPair = await generateDeviceKeyPair();
    privB64 = await exportDevicePrivateKey(deviceKeyPair.privateKey);
    pubB64 = await exportDevicePublicKey(deviceKeyPair.publicKey);
  }

  const deviceId = getDeviceId();
  const { masterKey: prfKey } = await derivePrfMasterKey();
  const prfMethodId = await getPrfMethodId(prfKey);

  const credentialId = local.getPrfCredentialId(uid) || "default_prf";

  const { doc, rawAmk } = await prepareGenesisDocument(
    deviceId,
    getDeviceName(),
    pubB64,
    credentialId,
    prfKey,
    prfMethodId
  );

  // Commit to Firestore first
  await store.setAccountKeys(doc);

  // Only persist device keys after Firestore succeeds (safe for both fresh + retry)
  await local.saveDeviceKeys({ privateKey: privB64, publicKey: pubB64 });

  const amk = await getCrypto().importSymmetricKey(new Uint8Array(rawAmk) as RawKeyBytes);

  return { amk, amkId: doc.activeAmkId };
}

export async function enablePrfRecovery(): Promise<void> {
  const user = auth.getCurrentUser();
  if (!user) throw new Error("Must be signed in.");

  const { amk, amkId } = await getActiveAmk();
  const rawAmk = await getCrypto().exportSymmetricKey(amk);
  
  const { masterKey: prfKey } = await derivePrfMasterKey();
  const prfMethodId = await getPrfMethodId(prfKey);
  const credentialId = local.getPrfCredentialId(user.uid) || "default_prf";

  const amkB64 = btoa(String.fromCharCode(...new Uint8Array(rawAmk)));
  const { ciphertext: prfCipher, iv: prfIv } = await encrypt(prfKey, amkB64);
  const wrappedForPrf = btoa(JSON.stringify({ ciphertext: prfCipher, iv: prfIv }));

  await store.transactAccountKeys(async (current) => {
    // M4 FIX: TOCTOU guard — verify the AMK hasn't been rotated since we read it.
    // If it has, our wrappedForPrf contains the wrong AMK and we must abort.
    if (current.activeAmkId !== amkId) {
      throw new Error(
        `[charproof] AMK rotated during enablePrfRecovery (expected ${amkId}, got ${current.activeAmkId}). ` +
        `Aborting to prevent sealing the wrong key version. Retry to use the current AMK.`
      );
    }
    const encryptedRecLabel = await encryptPayload(amk, `Passkey on ${getDeviceName()}`);
    current.recoveryMethods[prfMethodId] = {
      type: 'prf',
      encryptedLabel: encryptedRecLabel,
      credentialId: credentialId,
      createdAt: Date.now()
    };
    current.keyring[amkId][prfMethodId] = wrappedForPrf;
    return current;
  });
}

export async function revokeDevice(revokedDeviceId: string) {
  const { amk: oldAmk } = await getActiveAmk();
  const newAmk = await generateSymmetricKey(256);
  const newAmkId = `amk_${Date.now()}`;

  let prfKey: AesGcmKey | undefined;
  try {
    const derived = await derivePrfMasterKey();
    prfKey = derived.masterKey;
  } catch (e) {
    console.warn("Could not automatically derive PRF recovery keys during revocation:", e);
  }

  await store.transactAccountKeys(async (current) => {
    return rotateKeys(
      revokedDeviceId,
      current,
      oldAmk,
      newAmk,
      newAmkId,
      prfKey
    );
  });

  // H3 FIX: Wrap post-transaction cache update in try/catch.
  // If this fails, clear the cache so the next getActiveAmk() call can self-heal
  // by re-deriving the AMK from the already-rotated Firestore document.
  try {
    const rawNewAmk = await exportSymmetricKey(newAmk);
    const amkBuffer = base64UrlToUint8(rawNewAmk);
    cachedAmk = await getCrypto().importSymmetricKey(new Uint8Array(amkBuffer.buffer as ArrayBuffer) as RawKeyBytes);
    cachedAmkId = newAmkId;
  } catch (e) {
    console.warn("[charproof] Post-rotation cache update failed. Clearing cache for self-healing.", e);
    clearAmkSessionCache();
  }
}

export async function saveToKeystore(ledgerId: string, payload: LedgerCredentials) {
  const { amk, amkId } = await getActiveAmk();
  
  // Encrypt the ledgerId INSIDE the payload envelope for zero-knowledge metadata privacy
  const envelope = {
    ledgerId,
    ...payload
  };
  const json = JSON.stringify(envelope);
  const encrypted = await encryptPayload(amk, json);

  // Blind the document ID (ledgerId) using the AMK-derived key
  const docId = await blindLedgerId(amk, ledgerId);

  await store.setKeystoreEntry(docId, {
    amkId,
    ...encrypted,
    updatedAt: Date.now()
  });
}

export async function loadFromKeystore(ledgerId: string): Promise<LedgerCredentials | null> {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) return null;

  const { amk: activeAmk } = await getActiveAmk();
  
  // Try with the active AMK first (which is the most common case)
  const activeDocId = await blindLedgerId(activeAmk, ledgerId);
  let entry = await store.getKeystoreEntry(activeDocId);
  
  // If not found, look up using any historical AMKs available to this device
  if (!entry) {
    const deviceId = getDeviceId();
    const accountKeys = await store.getAccountKeys();
    if (accountKeys) {
      const amkIds = Object.keys(accountKeys.keyring).filter(
        id => accountKeys.keyring[id]?.[deviceId] && id !== accountKeys.activeAmkId
      );
      for (const amkId of amkIds) {
        try {
          const historicalAmk = await getAmkById(amkId);
          const historicalDocId = await blindLedgerId(historicalAmk, ledgerId);
          const historicalEntry = await store.getKeystoreEntry(historicalDocId);
          if (historicalEntry) {
            entry = historicalEntry;
            break;
          }
        } catch (e) {
          // If unwrapping a specific historical AMK fails, skip it
          continue;
        }
      }
    }
  }

  if (!entry) return null;

  const entryAmk = await getAmkById(entry.amkId);
  const json = await decryptPayload(entryAmk, entry);
  const decrypted = JSON.parse(json);

  // If the decrypted payload was saved in the legacy format, it is directly the credentials.
  // Otherwise, it has { ledgerId, ...credentials }. We extract only the LedgerCredentials fields.
  return {
    symmetricKey: decrypted.symmetricKey,
    signingPrivateKey: decrypted.signingPrivateKey,
    signingPublicKey: decrypted.signingPublicKey
  };
}

export async function hasAccountKeys(): Promise<boolean> {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) return false;
  try {
    const keys = await store.getAccountKeys();
    return !!keys;
  } catch (e) {
    console.error("Failed to fetch account keys:", e);
    return false;
  }
}

export async function verifyAmk(): Promise<boolean> {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) return true;

  try {
    await getActiveAmk();
    return true;
  } catch (e) {
    console.error("AMK verification failed:", e);
    return false;
  }
}

export async function requestDeviceAuthorization(): Promise<void> {
  const deviceId = getDeviceId();
  const deviceKeyPair = await generateDeviceKeyPair();
  const pubB64 = await exportDevicePublicKey(deviceKeyPair.publicKey);
  const privB64 = await exportDevicePrivateKey(deviceKeyPair.privateKey);

  await local.saveDeviceKeys({ privateKey: privB64, publicKey: pubB64 });

  const accountKeys = await store.getAccountKeys();
  if (!accountKeys) throw new Error("Account keys document missing.");

  const pendingData = await preparePendingDeviceRequest(
    deviceId,
    getDeviceName(),
    pubB64,
    accountKeys
  );

  await store.setPendingDevice(deviceId, pendingData);
}

export async function approveDeviceAuthorization(pendingDevice: PendingDevice): Promise<void> {
  const currentDeviceId = getDeviceId();
  const localKeys = await local.loadDeviceKeys();
  if (!localKeys) throw new Error("Local device keys missing.");

  const { amk, amkId } = await getActiveAmk();

  const { wrappedAmk, encryptedNameWithAmk } = await preparePendingDeviceApproval(
    currentDeviceId,
    localKeys.privateKey,
    pendingDevice,
    amk,
    amkId
  );

  await store.transactApproveDevice(
    (current) => {
      current.devices[pendingDevice.deviceId] = {
        deviceId: pendingDevice.deviceId,
        encryptedDeviceName: encryptedNameWithAmk,
        publicKey: pendingDevice.publicKey,
        createdAt: Date.now()
      };
      current.keyring[amkId][pendingDevice.deviceId] = wrappedAmk;
      return current;
    },
    pendingDevice.deviceId,
    { status: 'authorized' }
  );
}

export async function loadDeviceKeysFromIndexedDB(): Promise<{ privateKey: string; publicKey: string } | null> {
  return local.loadDeviceKeys();
}

export async function getLocalPublicKey(): Promise<string | null> {
  const keys = await local.loadDeviceKeys();
  return keys ? keys.publicKey : null;
}

export interface DecryptedDevice {
  deviceId: string;
  decryptedDeviceName: string;
  publicKey: string;
  createdAt: number;
}

export function subscribePendingRequests(
  onUpdate: (requests: PendingDevice[]) => void,
  onError?: (err: Error) => void
): () => void {
  const currentDeviceId = getDeviceId();
  
  return store.subscribePendingDevices(async (rawRequests) => {
    try {
      const now = Date.now();
      const filteredRequests = rawRequests.filter(
        d => d.deviceId !== currentDeviceId && (!d.expiresAt || d.expiresAt > now)
      );

      const decryptedRequests: PendingDevice[] = [];
      const localKeys = await local.loadDeviceKeys();

      if (localKeys) {
        const localPrivateKey = await importDevicePrivateKey(localKeys.privateKey);

        for (const req of filteredRequests) {
          try {
            const wrappedKeyForUs = req.encryptedDeviceName.wrappedKeys[currentDeviceId];
            if (wrappedKeyForUs) {
              const decryptedName = await decryptHybrid(
                localPrivateKey,
                req.encryptedDeviceName,
                wrappedKeyForUs
              );
              (req as any).decryptedDeviceName = decryptedName;
            } else {
              (req as any).decryptedDeviceName = "Unknown Device";
            }
          } catch (err) {
            console.error("Failed to decrypt pending device name:", err);
            (req as any).decryptedDeviceName = "Unreadable Device Name";
          }
          decryptedRequests.push(req);
        }
      } else {
        for (const req of filteredRequests) {
          (req as any).decryptedDeviceName = "Unknown Device";
          decryptedRequests.push(req);
        }
      }

      onUpdate(decryptedRequests);
    } catch (err: any) {
      console.error("subscribePendingRequests failed:", err);
      onError?.(err);
    }
  });
}

export function subscribeAuthorizedDevices(
  onUpdate: (devices: DecryptedDevice[]) => void,
  onError?: (err: Error) => void
): () => void {
  return store.subscribeAccountKeys(async (accountKeys) => {
    try {
      if (!accountKeys) {
        onUpdate([]);
        return;
      }

      const { amk } = await getActiveAmk();
      const decryptedList: DecryptedDevice[] = [];

      for (const [deviceId, device] of Object.entries(accountKeys.devices)) {
        let plainName = "Unreadable Device";
        try {
          plainName = await decryptPayload(amk, device.encryptedDeviceName);
        } catch (err) {
          console.error(`Failed to decrypt device name for ${deviceId}:`, err);
        }
        decryptedList.push({
          deviceId,
          decryptedDeviceName: plainName,
          publicKey: device.publicKey,
          createdAt: device.createdAt
        });
      }

      onUpdate(decryptedList);
    } catch (err: any) {
      console.error("subscribeAuthorizedDevices failed:", err);
      onError?.(err);
    }
  });
}

export function subscribeCurrentDeviceStatus(
  onAuthorized: () => void,
  onError?: (err: Error) => void
): () => void {
  const currentDeviceId = getDeviceId();
  return store.subscribePendingDevice(currentDeviceId, (device) => {
    try {
      if (device && device.status === "authorized") {
        onAuthorized();
      }
    } catch (err: any) {
      console.error("subscribeCurrentDeviceStatus failed:", err);
      onError?.(err);
    }
  });
}

export function subscribeToUserKeystore(
  onUpdate: (entries: DecryptedKeystoreEntry[]) => void,
  onError?: (err: Error) => void
): () => void {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) {
    onUpdate([]);
    return () => {};
  }
  return store.subscribeKeystore(async (entries) => {
    try {
      const processed = await Promise.all(
        entries.map(async (entry) => {
          try {
            // Decrypt the entry to retrieve the ledgerId from the secure envelope.
            const amk = await getAmkById(entry.amkId);
            const json = await decryptPayload(amk, entry);
            const decrypted = JSON.parse(json);
            return {
              ...entry,
              ledgerId: decrypted.ledgerId
            };
          } catch (e) {
            // Decryption might fail if active keys are not initialized yet, fallback to the entry.
            return entry;
          }
        })
      );
      onUpdate(processed);
    } catch (err: any) {
      console.error("subscribeToUserKeystore mapping failed:", err);
      // Fallback: update with the original entries if the entire mapping fails
      onUpdate(entries);
    }
  });
}

export async function rejectDeviceRequest(deviceId: string): Promise<void> {
  await store.deletePendingDevice(deviceId);
}

export async function resetLocalStorage(): Promise<void> {
  await local.clearAll();
  clearAmkSessionCache();
}

export async function resetUserAccountRemote(): Promise<void> {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) return;
  await store.resetRemoteStore();
}

async function getBlindedKeystoreDocId(ledgerId: string): Promise<string | null> {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) return null;

  const { amk: activeAmk } = await getActiveAmk();
  const activeDocId = await blindLedgerId(activeAmk, ledgerId);
  const entry = await store.getKeystoreEntry(activeDocId);
  if (entry) return activeDocId;

  const deviceId = getDeviceId();
  const accountKeys = await store.getAccountKeys();
  if (accountKeys) {
    const amkIds = Object.keys(accountKeys.keyring).filter(
      id => accountKeys.keyring[id]?.[deviceId] && id !== accountKeys.activeAmkId
    );
    for (const amkId of amkIds) {
      try {
        const historicalAmk = await getAmkById(amkId);
        const historicalDocId = await blindLedgerId(historicalAmk, ledgerId);
        const historicalEntry = await store.getKeystoreEntry(historicalDocId);
        if (historicalEntry) {
          return historicalDocId;
        }
      } catch (e) {
        continue;
      }
    }
  }
  return null;
}

export async function archiveKeystoreEntry(ledgerId: string): Promise<void> {
  const docId = await getBlindedKeystoreDocId(ledgerId);
  if (!docId) {
    throw new Error(`Keystore entry for ledger ${ledgerId} not found.`);
  }
  await store.setKeystoreArchivedStatus(docId, true);
}

export async function unarchiveKeystoreEntry(ledgerId: string): Promise<void> {
  const docId = await getBlindedKeystoreDocId(ledgerId);
  if (!docId) {
    throw new Error(`Keystore entry for ledger ${ledgerId} not found.`);
  }
  await store.setKeystoreArchivedStatus(docId, false);
}

