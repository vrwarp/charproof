import {
  openDB,
  STORE_DEVICE_KEYS,
  STORE_MASTER_KEYS,
  STORE_IDENTITIES
} from "../idb";
import type { LocalDeviceStore, AesGcmKey } from "../core/interfaces";

export class BrowserLocalDeviceStore implements LocalDeviceStore {
  private useMemoryFallback = false;
  private memoryStore: Record<string, Map<string, any>> = {
    [STORE_DEVICE_KEYS]: new Map(),
    [STORE_MASTER_KEYS]: new Map(),
    [STORE_IDENTITIES]: new Map(),
  };

  private async getDatabase(): Promise<IDBDatabase | null> {
    if (this.useMemoryFallback) return null;
    try {
      return await openDB();
    } catch (err) {
      console.warn("[charproof] IndexedDB failed to open. Falling back to in-memory store.", err);
      this.useMemoryFallback = true;
      return null;
    }
  }

  getDeviceId(): string {
    let deviceId: string | null = null;
    try {
      deviceId = localStorage.getItem("deviceId");
    } catch (e) {}
    if (!deviceId) {
      deviceId = crypto.randomUUID();
      try {
        localStorage.setItem("deviceId", deviceId);
      } catch (e) {}
    }
    return deviceId;
  }

  getDeviceName(): string {
    try {
      return localStorage.getItem("deviceName") || "Unknown Device";
    } catch (e) {
      return "Unknown Device";
    }
  }

  setDeviceName(name: string): void {
    try {
      localStorage.setItem("deviceName", name);
    } catch (e) {}
  }

  async saveDeviceKeys(keys: { privateKey: string; publicKey: string }): Promise<void> {
    const db = await this.getDatabase();
    if (!db) {
      this.memoryStore[STORE_DEVICE_KEYS].set("current_device", keys);
      return;
    }
    const tx = db.transaction(STORE_DEVICE_KEYS, "readwrite");
    tx.objectStore(STORE_DEVICE_KEYS).put(keys, "current_device");
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async loadDeviceKeys(): Promise<{ privateKey: string; publicKey: string } | null> {
    const db = await this.getDatabase();
    if (!db) {
      return this.memoryStore[STORE_DEVICE_KEYS].get("current_device") || null;
    }
    const tx = db.transaction(STORE_DEVICE_KEYS, "readonly");
    const request = tx.objectStore(STORE_DEVICE_KEYS).get("current_device");
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  async saveMasterKey(uid: string, key: AesGcmKey): Promise<void> {
    const db = await this.getDatabase();
    if (!db) {
      this.memoryStore[STORE_MASTER_KEYS].set(uid, key);
      return;
    }
    const tx = db.transaction(STORE_MASTER_KEYS, "readwrite");
    tx.objectStore(STORE_MASTER_KEYS).put(key, uid);
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async loadMasterKey(uid: string): Promise<AesGcmKey | null> {
    const db = await this.getDatabase();
    if (!db) {
      return this.memoryStore[STORE_MASTER_KEYS].get(uid) || null;
    }
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
    const db = await this.getDatabase();
    if (!db) {
      this.memoryStore[STORE_IDENTITIES].set(ledgerId, keys);
      return;
    }
    const tx = db.transaction(STORE_IDENTITIES, "readwrite");
    tx.objectStore(STORE_IDENTITIES).put(keys, ledgerId);
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async loadIdentity(ledgerId: string): Promise<{ privateKey: string; publicKey: string } | null> {
    const db = await this.getDatabase();
    if (!db) {
      return this.memoryStore[STORE_IDENTITIES].get(ledgerId) || null;
    }
    const tx = db.transaction(STORE_IDENTITIES, "readonly");
    const request = tx.objectStore(STORE_IDENTITIES).get(ledgerId);
    return new Promise((resolve) => {
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => resolve(null);
    });
  }

  getPrfCredentialId(uid: string): string | null {
    const storageKey = `prf_cred_${uid}`;
    try {
      return localStorage.getItem(storageKey);
    } catch (e) {
      return null;
    }
  }

  setPrfCredentialId(uid: string, credentialId: string): void {
    const storageKey = `prf_cred_${uid}`;
    try {
      localStorage.setItem(storageKey, credentialId);
    } catch (e) {}
  }

  async clearAll(): Promise<void> {
    const db = await this.getDatabase();
    if (!db) {
      this.memoryStore[STORE_DEVICE_KEYS].clear();
      this.memoryStore[STORE_MASTER_KEYS].clear();
      this.memoryStore[STORE_IDENTITIES].clear();
      try {
        localStorage.removeItem("deviceId");
        localStorage.removeItem("deviceName");

        for (let i = localStorage.length - 1; i >= 0; i--) {
          const key = localStorage.key(i);
          if (key && key.startsWith("prf_cred_")) {
            localStorage.removeItem(key);
          }
        }
      } catch (e) {}
      return;
    }
    const tx = db.transaction([STORE_DEVICE_KEYS, STORE_MASTER_KEYS, STORE_IDENTITIES], "readwrite");
    tx.objectStore(STORE_DEVICE_KEYS).clear();
    tx.objectStore(STORE_MASTER_KEYS).clear();
    tx.objectStore(STORE_IDENTITIES).clear();

    return new Promise((resolve, reject) => {
      tx.oncomplete = () => {
        try {
          localStorage.removeItem("deviceId");
          localStorage.removeItem("deviceName");

          for (let i = localStorage.length - 1; i >= 0; i--) {
            const key = localStorage.key(i);
            if (key && key.startsWith("prf_cred_")) {
              localStorage.removeItem(key);
            }
          }
        } catch (e) {}
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  }
}
