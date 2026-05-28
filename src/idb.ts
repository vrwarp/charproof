export const DB_NAME = "LetUsMeet_Keys";
export const DB_VERSION = 3; // Incremented to ensure all stores are created
export const STORE_IDENTITIES = "identities";
export const STORE_MASTER_KEYS = "master_keys";
export const STORE_DEVICE_KEYS = "device_keys";

export async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    // M5 FIX: Timeout to prevent indefinite hangs when another tab blocks the upgrade
    const timeout = setTimeout(() => {
      reject(new Error("[charproof] IndexedDB open timed out after 10s. Another tab may be blocking the upgrade."));
    }, 10000);

    request.onblocked = () => {
      console.warn("[charproof] IndexedDB upgrade blocked by another tab. Close other tabs and retry.");
    };
    
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_IDENTITIES)) {
        db.createObjectStore(STORE_IDENTITIES);
      }
      if (!db.objectStoreNames.contains(STORE_MASTER_KEYS)) {
        db.createObjectStore(STORE_MASTER_KEYS);
      }
      if (!db.objectStoreNames.contains(STORE_DEVICE_KEYS)) {
        db.createObjectStore(STORE_DEVICE_KEYS);
      }
    };
    
    request.onsuccess = () => {
      clearTimeout(timeout);
      resolve(request.result);
    };
    request.onerror = () => {
      clearTimeout(timeout);
      reject(request.error);
    };
  });
}
