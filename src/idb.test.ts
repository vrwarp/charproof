import { describe, it, expect, vi, beforeEach } from "vitest";
import { DB_NAME, DB_VERSION, STORE_IDENTITIES, STORE_MASTER_KEYS, STORE_DEVICE_KEYS, openDB } from "./idb";
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";

describe("idb", () => {
  beforeEach(() => {
    // Reset indexedDB state before each test
    globalThis.indexedDB = new IDBFactory();
  });

  it("should have correct constants", () => {
    expect(DB_NAME).toBe("LetUsMeet_Keys");
    expect(DB_VERSION).toBe(3);
    expect(STORE_IDENTITIES).toBe("identities");
    expect(STORE_MASTER_KEYS).toBe("master_keys");
    expect(STORE_DEVICE_KEYS).toBe("device_keys");
  });

  it("should open database and create all required object stores on upgradeneeded", async () => {
    const db = await openDB();

    expect(db.name).toBe(DB_NAME);
    expect(db.version).toBe(DB_VERSION);

    // Verify all stores exist
    expect(db.objectStoreNames.contains(STORE_IDENTITIES)).toBe(true);
    expect(db.objectStoreNames.contains(STORE_MASTER_KEYS)).toBe(true);
    expect(db.objectStoreNames.contains(STORE_DEVICE_KEYS)).toBe(true);

    db.close();
  });

  it("should allow storing and retrieving data in all stores", async () => {
    const db = await openDB();

    // Helper function to write to a store
    const writeToStore = (storeName: string, key: string, value: any): Promise<void> => {
      return new Promise((resolve, reject) => {
        const transaction = db.transaction(storeName, "readwrite");
        const store = transaction.objectStore(storeName);
        const request = store.put(value, key);

        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    };

    // Helper function to read from a store
    const readFromStore = (storeName: string, key: string): Promise<any> => {
      return new Promise((resolve, reject) => {
        const transaction = db.transaction(storeName, "readonly");
        const store = transaction.objectStore(storeName);
        const request = store.get(key);

        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    };

    const testData = { id: "test-123", secret: "super-secret" };

    // Write data
    await writeToStore(STORE_IDENTITIES, "id-key", { ...testData, type: 'identity' });
    await writeToStore(STORE_MASTER_KEYS, "mk-key", { ...testData, type: 'master' });
    await writeToStore(STORE_DEVICE_KEYS, "dk-key", { ...testData, type: 'device' });

    // Read and verify data
    const idResult = await readFromStore(STORE_IDENTITIES, "id-key");
    const mkResult = await readFromStore(STORE_MASTER_KEYS, "mk-key");
    const dkResult = await readFromStore(STORE_DEVICE_KEYS, "dk-key");

    expect(idResult).toEqual({ ...testData, type: 'identity' });
    expect(mkResult).toEqual({ ...testData, type: 'master' });
    expect(dkResult).toEqual({ ...testData, type: 'device' });

    db.close();
  });

  it("should handle partial database upgrades (adding missing stores)", async () => {
    // 1. Manually create an older version of the DB with only one store
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore(STORE_IDENTITIES);
      };
      req.onsuccess = () => {
        req.result.close();
        resolve();
      };
      req.onerror = () => reject(req.error);
    });

    // 2. Now call openDB(), which asks for DB_VERSION (3).
    // It should trigger onupgradeneeded and create the remaining stores.
    const db = await openDB();

    expect(db.version).toBe(DB_VERSION);
    expect(db.objectStoreNames.contains(STORE_IDENTITIES)).toBe(true);
    expect(db.objectStoreNames.contains(STORE_MASTER_KEYS)).toBe(true);
    expect(db.objectStoreNames.contains(STORE_DEVICE_KEYS)).toBe(true);

    db.close();
  });

  it("should handle existing database without re-creating stores", async () => {
    // First call to create the DB and stores
    const db1 = await openDB();

    // Store some data
    await new Promise<void>((resolve, reject) => {
      const transaction = db1.transaction(STORE_IDENTITIES, "readwrite");
      transaction.objectStore(STORE_IDENTITIES).put({ test: true }, "existing-key");
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });

    db1.close();

    // Second call should succeed and return the existing DB without error
    const db2 = await openDB();

    // Verify the data still exists (meaning the store wasn't wiped/re-created destructively)
    const data = await new Promise((resolve, reject) => {
      const transaction = db2.transaction(STORE_IDENTITIES, "readonly");
      const request = transaction.objectStore(STORE_IDENTITIES).get("existing-key");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    expect(data).toEqual({ test: true });

    db2.close();
  });

  it("should handle indexedDB open errors", async () => {
    const originalOpen = globalThis.indexedDB.open;

    // Mock the open method to simulate a failure
    globalThis.indexedDB.open = vi.fn().mockImplementation(() => {
      const request = {
        get error() { return new DOMException("Simulated IDB Open Error"); }
      } as unknown as IDBOpenDBRequest;

      setTimeout(() => {
        if (request.onerror) request.onerror(new Event("error"));
      }, 0);

      return request;
    });

    await expect(openDB()).rejects.toThrow("Simulated IDB Open Error");

    // Restore original
    globalThis.indexedDB.open = originalOpen;
  });
});
