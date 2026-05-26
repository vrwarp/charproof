export const DB_NAME = "LetUsMeet_Keys";
export const DB_VERSION = 3; // Incremented to ensure all stores are created
export const STORE_IDENTITIES = "identities";
export const STORE_MASTER_KEYS = "master_keys";
export const STORE_DEVICE_KEYS = "device_keys";

export async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    
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
    
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
