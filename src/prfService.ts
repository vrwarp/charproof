import type { AesGcmKey, LocalDeviceStore, AuthProvider, PrfProvider } from "./core/interfaces";
import { BrowserLocalDeviceStore } from "./browser/BrowserLocalDeviceStore";
import { FirebaseAuthProvider } from "./browser/FirebaseAuthProvider";
import { WebAuthnPrfProvider } from "./browser/WebAuthnPrfProvider";
import { getCrypto } from "./core/crypto";

let local: LocalDeviceStore = new BrowserLocalDeviceStore();
let auth: AuthProvider = new FirebaseAuthProvider();
let prf: PrfProvider = new WebAuthnPrfProvider();

export function setPrfProviders(providers: {
  localDeviceStore?: LocalDeviceStore;
  authProvider?: AuthProvider;
  prfProvider?: PrfProvider;
}) {
  if (providers.localDeviceStore) local = providers.localDeviceStore;
  if (providers.authProvider) auth = providers.authProvider;
  if (providers.prfProvider) prf = providers.prfProvider;
}

export async function loadMasterKeyFromIndexedDB(uid: string): Promise<AesGcmKey | null> {
  return local.loadMasterKey(uid);
}

let prfPromise: Promise<{ masterKey: AesGcmKey, usedCredentialId: string }> | null = null;
let globalPrfLock: Promise<any> = Promise.resolve();

export function clearPrfSessionCache() {
  prfPromise = null;
  globalPrfLock = Promise.resolve();
}

export async function derivePrfMasterKey(credentialIds?: string[]): Promise<{ masterKey: AesGcmKey, usedCredentialId: string }> {
  // If we already have a successful derivation in this session, return it immediately
  if (prfPromise) return prfPromise;

  // Use the lock to ensure sequential execution of ANY WebAuthn request
  const resultPromise = (async () => {
    await globalPrfLock;

    try {
      const user = auth.getCurrentUser();
      if (!user) throw new Error("Must be signed in to derive PRF key.");

      // For silent check (no IDs provided), check IndexedDB
      if (!credentialIds || credentialIds.length === 0) {
        const cachedKey = await loadMasterKeyFromIndexedDB(user.uid);
        if (cachedKey) {
          return { masterKey: cachedKey, usedCredentialId: "cached" };
        }
      }

      const storageKey = `prf_cred_${user.uid}`;
      const effectiveIds = (credentialIds && credentialIds.length > 0)
        ? credentialIds
        : [localStorage.getItem(storageKey)].filter(Boolean) as string[];

      let prfResult: Uint8Array;
      let usedId: string;

      if (effectiveIds.length === 0) {
        // Create new credential logic
        const creation = await prf.createCredential(user.uid, user.email || user.uid, user.displayName || user.uid);
        usedId = creation.credentialId;
        prfResult = creation.prfResult;
      } else {
        // Get assertion
        const assertion = await prf.getAssertion(effectiveIds);
        usedId = assertion.usedCredentialId;
        prfResult = assertion.prfResult;
      }

      // Reconstitute Master Key
      const masterKey = await getCrypto().importSymmetricKey(prfResult.slice(0, 16) as any);

      // Always update local storage and IndexedDB with the successfully used credential
      local.setPrfCredentialId(user.uid, usedId);
      await local.saveMasterKey(user.uid, masterKey);

      return { masterKey, usedCredentialId: usedId };
    } catch (e) {
      throw e;
    }
  })();

  globalPrfLock = resultPromise.catch(() => { }).then(() => { });

  // Cache the promise for the session
  prfPromise = resultPromise;
  resultPromise.catch(() => {
    // If the derivation fails (e.g. user cancels), clear the cache so they can try again
    if (prfPromise === resultPromise) prfPromise = null;
  });

  return resultPromise;
}
