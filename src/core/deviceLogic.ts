import type {
  AesGcmKey,
  RsaOaepPrivateKey,
  WrappedKeyBytes,
  Pkcs8Bytes,
  PlaintextBytes,
  CiphertextBytes,
  IvBytes
} from "./interfaces";
import type {
  AccountKeysDocument,
  PendingDevice,
  DevicePublicKey,
  EncryptedData
} from "./types";
import {
  generateSymmetricKey,
  importDevicePrivateKey,
  importDevicePublicKey,
  unwrapAmk,
  wrapAmk,
  encryptPayload,
  decryptPayload,
  decrypt,
  encrypt,
  getCrypto
} from "./crypto";
import { base64ToUint8 } from "./base64";

/**
 * Safely parses a base64-encoded `{ ciphertext, iv }` envelope that originates
 * from the untrusted database. Throws a clear, typed error instead of letting a
 * malformed or hostile document throw deep inside the crypto layer.
 */
export function parseEncryptedEnvelopeB64(b64: string): { ciphertext: string; iv: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(atob(b64));
  } catch (e) {
    throw new Error("MALFORMED_ENVELOPE: wrapped payload is not valid base64-encoded JSON.");
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    typeof (parsed as any).ciphertext !== "string" ||
    typeof (parsed as any).iv !== "string"
  ) {
    throw new Error("MALFORMED_ENVELOPE: wrapped payload missing string `ciphertext`/`iv` fields.");
  }
  return { ciphertext: (parsed as any).ciphertext, iv: (parsed as any).iv };
}

export async function unwrapActiveAmk(
  data: AccountKeysDocument,
  deviceId: string,
  devicePrivateKeyB64: string
): Promise<ArrayBuffer> {
  const amkId = data.activeAmkId;
  return unwrapAmkById(data, deviceId, devicePrivateKeyB64, amkId);
}

export async function unwrapAmkById(
  data: AccountKeysDocument,
  deviceId: string,
  devicePrivateKeyB64: string,
  targetAmkId: string
): Promise<ArrayBuffer> {
  const wrappedAmkBase64 = data.keyring[targetAmkId]?.[deviceId];
  if (!wrappedAmkBase64) {
    throw new Error(`UNRECOGNIZED_DEVICE: AMK ${targetAmkId} not found or not wrapped for this device.`);
  }

  const privateKey = await importDevicePrivateKey(devicePrivateKeyB64);
  return unwrapAmk(privateKey, wrappedAmkBase64);
}


export async function tryRecoverAmkWithPrfKey(
  data: AccountKeysDocument,
  prfMasterKey: AesGcmKey,
  methodId: string
): Promise<{ amkRaw: ArrayBuffer; amkId: string } | null> {
  const amkId = data.activeAmkId;
  const keyring = data.keyring[amkId] || {};
  const wrappedAmk = keyring[methodId];

  if (!wrappedAmk) {
    return null;
  }

  const parsed = parseEncryptedEnvelopeB64(wrappedAmk);
  const cipherBytes = base64ToUint8(parsed.ciphertext) as CiphertextBytes;
  const ivBytes = base64ToUint8(parsed.iv) as IvBytes;
  
  const decryptedBytes = await getCrypto().decrypt(prfMasterKey, cipherBytes, ivBytes);
  const amkB64 = new TextDecoder().decode(decryptedBytes);
  const amkRaw = base64ToUint8(amkB64).buffer as ArrayBuffer;

  return { amkRaw, amkId };
}

export async function prepareGenesisDocument(
  deviceId: string,
  deviceName: string,
  devicePubB64: string,
  credentialId?: string,
  prfKey?: AesGcmKey,
  prfMethodId?: string
): Promise<{ doc: AccountKeysDocument; rawAmk: ArrayBuffer }> {
  // Generate initial AMK (amk_v1)
  const amk = await generateSymmetricKey(256);
  const amkId = "amk_v1";
  const rawAmk = await getCrypto().exportSymmetricKey(amk);

  // Wrap AMK for genesis device
  const devicePubKey = await importDevicePublicKey(devicePubB64);
  const wrappedAmk = await wrapAmk(devicePubKey, rawAmk.buffer as ArrayBuffer);

  const encryptedDevName = await encryptPayload(amk, deviceName);

  // The device wrapping alone makes the account fully usable on this device.
  // PRF is an OPTIONAL recovery custodian: when a PRF key is supplied we seal a
  // second wrapping and register the recovery method; when it is not (e.g. the
  // authenticator can't provision hmac-secret), genesis still completes as a
  // device-key-only account and a recovery method can be sealed later via
  // enablePrfRecovery()/setupPhraseRecovery().
  const recoveryMethods: AccountKeysDocument["recoveryMethods"] = {};
  const keyringForAmk: Record<string, string> = { [deviceId]: wrappedAmk };

  if (prfKey && prfMethodId) {
    const amkB64 = btoa(String.fromCharCode(...new Uint8Array(rawAmk)));
    const plainBytes = new TextEncoder().encode(amkB64) as PlaintextBytes;
    const encryptedPrf = await getCrypto().encrypt(prfKey, plainBytes);
    const wrappedForPrf = btoa(JSON.stringify({
      ciphertext: uint8ToBase64(encryptedPrf.ciphertext),
      iv: uint8ToBase64(encryptedPrf.iv)
    }));
    const encryptedRecLabel = await encryptPayload(amk, `Passkey on ${deviceName}`);

    recoveryMethods[prfMethodId] = {
      type: 'prf',
      encryptedLabel: encryptedRecLabel,
      credentialId: credentialId ?? "default_prf",
      createdAt: Date.now()
    };
    keyringForAmk[prfMethodId] = wrappedForPrf;
  }

  const doc: AccountKeysDocument = {
    activeAmkId: amkId,
    devices: {
      [deviceId]: {
        deviceId,
        encryptedDeviceName: encryptedDevName,
        publicKey: devicePubB64,
        createdAt: Date.now()
      }
    },
    recoveryMethods,
    keyring: {
      [amkId]: keyringForAmk
    }
  };

  return { doc, rawAmk: rawAmk.buffer as ArrayBuffer };
}

export async function prepareRegistrationData(
  amk: AesGcmKey,
  amkId: string,
  deviceName: string,
  deviceId: string,
  devicePubB64: string,
  currentDoc: AccountKeysDocument
): Promise<AccountKeysDocument> {
  const rawAmk = await getCrypto().exportSymmetricKey(amk);
  const devicePubKey = await importDevicePublicKey(devicePubB64);
  const wrappedForNewDevice = await wrapAmk(devicePubKey, rawAmk.buffer as ArrayBuffer);

  const encryptedDevName = await encryptPayload(
    amk,
    `${deviceName} (Recovered ${new Date().toISOString().slice(0, 10)})`
  );

  const updatedDoc = JSON.parse(JSON.stringify(currentDoc)) as AccountKeysDocument;
  updatedDoc.devices[deviceId] = {
    deviceId,
    encryptedDeviceName: encryptedDevName,
    publicKey: devicePubB64,
    createdAt: Date.now()
  };
  
  if (!updatedDoc.keyring[amkId]) {
    updatedDoc.keyring[amkId] = {};
  }
  updatedDoc.keyring[amkId][deviceId] = wrappedForNewDevice;

  return updatedDoc;
}

export async function rotateKeys(
  revokedDeviceId: string,
  currentDoc: AccountKeysDocument,
  oldAmk: AesGcmKey,
  newAmk: AesGcmKey,
  newAmkId: string,
  prfKey?: AesGcmKey
): Promise<AccountKeysDocument> {
  const updatedDoc = JSON.parse(JSON.stringify(currentDoc)) as AccountKeysDocument;

  // Remove revoked device
  delete updatedDoc.devices[revokedDeviceId];

  // Purge the revoked device's wrapped-AMK entries from EVERY keyring version
  // (not just the new one). Otherwise the revoked device could still unwrap any
  // historical AMK it was granted, defeating revocation for past key versions.
  //
  // NOTE: This cannot retroactively protect ledger/keystore data the revoked
  // device already decrypted while authorized — revocation is forward-only for
  // data that was already accessible. See SECURITY.md ("Revocation semantics").
  for (const versionId in updatedDoc.keyring) {
    delete updatedDoc.keyring[versionId][revokedDeviceId];
  }

  // Re-encrypt remaining device names
  for (const deviceId in updatedDoc.devices) {
    const dev = updatedDoc.devices[deviceId];
    const plainName = await decryptPayload(oldAmk, dev.encryptedDeviceName);
    dev.encryptedDeviceName = await encryptPayload(newAmk, plainName);
  }

  // Re-encrypt recovery labels
  for (const methodId in updatedDoc.recoveryMethods) {
    const method = updatedDoc.recoveryMethods[methodId];
    const plainLabel = await decryptPayload(oldAmk, method.encryptedLabel);
    method.encryptedLabel = await encryptPayload(newAmk, plainLabel);
  }

  // Create new keyring entry
  updatedDoc.keyring[newAmkId] = {};
  const rawNewAmk = await getCrypto().exportSymmetricKey(newAmk);

  // Wrap for remaining active devices
  for (const deviceId in updatedDoc.devices) {
    const devicePubB64 = updatedDoc.devices[deviceId].publicKey;
    const devicePubKey = await importDevicePublicKey(devicePubB64);
    const wrapped = await wrapAmk(devicePubKey, rawNewAmk.buffer as ArrayBuffer);
    updatedDoc.keyring[newAmkId][deviceId] = wrapped;
  }

  // Wrap for Phrase recovery
  if (updatedDoc.recoveryMethods) {
    for (const methodId in updatedDoc.recoveryMethods) {
      const method = updatedDoc.recoveryMethods[methodId];
      if (method.type === 'phrase' && method.publicKey) {
        const recoveryPubKey = await importDevicePublicKey(method.publicKey);
        const wrapped = await wrapAmk(recoveryPubKey, rawNewAmk.buffer as ArrayBuffer);
        updatedDoc.keyring[newAmkId][methodId] = wrapped;
      }
    }
  }

  // Wrap for PRF recovery if prfKey is provided
  if (prfKey && updatedDoc.recoveryMethods) {
    const amkB64 = btoa(String.fromCharCode(...new Uint8Array(rawNewAmk)));
    const plainBytes = new TextEncoder().encode(amkB64) as PlaintextBytes;
    const encryptedPrf = await getCrypto().encrypt(prfKey, plainBytes);
    const wrappedForPrf = btoa(JSON.stringify({
      ciphertext: uint8ToBase64(encryptedPrf.ciphertext),
      iv: uint8ToBase64(encryptedPrf.iv)
    }));

    for (const methodId in updatedDoc.recoveryMethods) {
      if (updatedDoc.recoveryMethods[methodId].type === 'prf') {
        updatedDoc.keyring[newAmkId][methodId] = wrappedForPrf;
      }
    }
  }

  updatedDoc.activeAmkId = newAmkId;
  return updatedDoc;
}

export async function preparePendingDeviceRequest(
  deviceId: string,
  deviceName: string,
  devicePubB64: string,
  accountKeysData: AccountKeysDocument
): Promise<PendingDevice> {
  const aesKey = await generateSymmetricKey(256);
  const encryptedName = await encryptPayload(aesKey, deviceName);
  const rawAesKey = await getCrypto().exportSymmetricKey(aesKey);
  const wrappedKeys: Record<string, string> = {};

  for (const [sponsorId, sponsorDevice] of Object.entries(accountKeysData.devices) as [string, DevicePublicKey][]) {
    const recipientPubKey = await importDevicePublicKey(sponsorDevice.publicKey);
    wrappedKeys[sponsorId] = await wrapAmk(recipientPubKey, rawAesKey.buffer as ArrayBuffer);
  }

  return {
    deviceId,
    encryptedDeviceName: {
      ...encryptedName,
      wrappedKeys
    },
    publicKey: devicePubB64,
    status: 'pending',
    createdAt: Date.now(),
    expiresAt: Date.now() + (5 * 60 * 1000)
  };
}

export async function preparePendingDeviceApproval(
  sponsorDeviceId: string,
  sponsorDevicePrivateKeyB64: string,
  pendingDevice: PendingDevice,
  activeAmk: AesGcmKey,
  activeAmkId: string
): Promise<{ wrappedAmk: string; encryptedNameWithAmk: EncryptedData; decryptedName: string }> {
  const wrappedKeyForUs = pendingDevice.encryptedDeviceName.wrappedKeys[sponsorDeviceId];
  if (!wrappedKeyForUs) {
    throw new Error("Pending request not wrapped for this device.");
  }

  const sponsorPrivateKey = await importDevicePrivateKey(sponsorDevicePrivateKeyB64);
  const wrappedBytes = base64ToUint8(wrappedKeyForUs) as WrappedKeyBytes;
  
  // Decrypt ephemeral key
  const aesKey = await getCrypto().unwrapKey(sponsorPrivateKey, wrappedBytes);
  const decryptedName = await decryptPayload(aesKey, pendingDevice.encryptedDeviceName);

  // Re-encrypt amk
  const rawAmk = await getCrypto().exportSymmetricKey(activeAmk);
  const targetPubKey = await importDevicePublicKey(pendingDevice.publicKey);
  const wrappedAmk = await wrapAmk(targetPubKey, rawAmk.buffer as ArrayBuffer);
  const encryptedNameWithAmk = await encryptPayload(activeAmk, decryptedName);

  return { wrappedAmk, encryptedNameWithAmk, decryptedName };
}

function uint8ToBase64(bytes: Uint8Array): string {
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
