import {
  openDB,
  STORE_DEVICE_KEYS,
  STORE_MASTER_KEYS,
  STORE_IDENTITIES
} from "../idb";
import type { LocalDeviceStore, AesGcmKey } from "../core/interfaces";

export class BrowserLocalDeviceStore implements LocalDeviceStore {
  getDeviceId(): string {
    let deviceId = localStorage.getItem("deviceId");
    if (!deviceId) {
      deviceId = crypto.randomUUID();
      localStorage.setItem("deviceId", deviceId);
    }
    return deviceId;
  }

  getDeviceName(): string {
    return localStorage.getItem("deviceName") || "Unknown Device";
  }

  setDeviceName(name: string): void {
    localStorage.setItem("deviceName", name);
  }

  async saveDeviceKeys(keys: { privateKey: string; publicKey: string }): Promise<void> {
    const db = await openDB();
    const tx = db.transaction(STORE_DEVICE_KEYS, "readwrite");
    tx.objectStore(STORE_DEVICE_KEYS).put(keys, "current_device");
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async loadDeviceKeys(): Promise<{ privateKey: string; publicKey: string } | null> {
    const db = await openDB();
    const tx = db.transaction(STORE_DEVICE_KEYS, "readonly");
    const request = tx.objectStore(STORE_DEVICE_KEYS).get("current_device");
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  async saveMasterKey(uid: string, key: AesGcmKey): Promise<void> {
    const db = await openDB();
    const tx = db.transaction(STORE_MASTER_KEYS, "readwrite");
    tx.objectStore(STORE_MASTER_KEYS).put(key, uid);
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async loadMasterKey(uid: string): Promise<AesGcmKey | null> {
    const db = await openDB();
    const tx = db.transaction(STORE_MASTER_KEYS, "readonly");
    const request = tx.objectStore(STORE_MASTER_KEYS).get(uid);
    return new Promise((resolve) => {
      request.onsuccess = () => {
        const key = request.result as CryptoKey | null;
        if (key && !key.extractable) {
          resolve(null); // Treat non-extractable keys as missing to force a fresh derivation
        } else {
          resolve(key as unknown as AesGcmKey);
        }
      };
      request.onerror = () => resolve(null);
    });
  }

  async saveIdentity(ledgerId: string, keys: { privateKey: string; publicKey: string }): Promise<void> {
    const db = await openDB();
    const tx = db.transaction(STORE_IDENTITIES, "readwrite");
    tx.objectStore(STORE_IDENTITIES).put(keys, ledgerId);
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async loadIdentity(ledgerId: string): Promise<{ privateKey: string; publicKey: string } | null> {
    const db = await openDB();
    const tx = db.transaction(STORE_IDENTITIES, "readonly");
    const request = tx.objectStore(STORE_IDENTITIES).get(ledgerId);
    return new Promise((resolve) => {
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => resolve(null);
    });
  }

  getPrfCredentialId(uid: string): string | null {
    const storageKey = `prf_cred_${uid}`;
    return localStorage.getItem(storageKey);
  }

  setPrfCredentialId(uid: string, credentialId: string): void {
    const storageKey = `prf_cred_${uid}`;
    localStorage.setItem(storageKey, credentialId);
  }

  async clearAll(): Promise<void> {
    const db = await openDB();
    const tx = db.transaction([STORE_DEVICE_KEYS, STORE_MASTER_KEYS, STORE_IDENTITIES], "readwrite");
    tx.objectStore(STORE_DEVICE_KEYS).clear();
    tx.objectStore(STORE_MASTER_KEYS).clear();
    tx.objectStore(STORE_IDENTITIES).clear();

    return new Promise((resolve, reject) => {
      tx.oncomplete = () => {
        // L3 FIX: Only clear localStorage after IndexedDB clears succeed
        // to prevent inconsistent state on partial failure.
        localStorage.removeItem("deviceId");
        localStorage.removeItem("deviceName");

        for (let i = localStorage.length - 1; i >= 0; i--) {
          const key = localStorage.key(i);
          if (key && key.startsWith("prf_cred_")) {
            localStorage.removeItem(key);
          }
        }

        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  }
}
