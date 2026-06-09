import { vi, describe, it, expect, beforeEach } from "vitest";
import { BrowserLocalDeviceStore } from "../../browser/BrowserLocalDeviceStore";
import { FirestoreAccountKeyStore } from "../../browser/FirestoreAccountKeyStore";
import { FirestoreLedgerEventStore } from "../../browser/FirestoreLedgerEventStore";
import { subscribeToUserKeystore } from "../../deviceService";
import { base64ToUint8 } from "../base64";
import * as idb from "../../idb";
import * as firestore from "firebase/firestore";

vi.mock("../../idb", async (importOriginal) => {
  const actual = await importOriginal<typeof idb>();
  return {
    ...actual,
    openDB: vi.fn(),
  };
});

vi.mock("firebase/firestore", () => {
  return {
    doc: vi.fn((...args) => ({ path: args.join("/") })),
    collection: vi.fn((...args) => ({ path: args.join("/") })),
    query: vi.fn((q) => q),
    orderBy: vi.fn(),
    limit: vi.fn(),
    serverTimestamp: vi.fn(() => "mock-timestamp"),
    getDoc: vi.fn(),
    getDocs: vi.fn(),
    onSnapshot: vi.fn((ref, onUpdate, onError) => {
      return () => {};
    }),
    writeBatch: vi.fn(() => ({
      set: vi.fn(),
      commit: vi.fn(),
    })),
  };
});

vi.mock("../../config", () => {
  return {
    getDb: vi.fn(() => ({})),
    getAuth: vi.fn(() => ({
      currentUser: { uid: "user-123" }
    })),
  };
});

describe("Resilience and Safe Degradation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    try {
      localStorage.clear();
    } catch (e) {}
  });

  describe("BrowserLocalDeviceStore - IndexedDB Deadlock Safe Degradation", () => {
    it("should fall back to in-memory store when openDB throws", async () => {
      const store = new BrowserLocalDeviceStore();
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      // Simulate IDB upgrade blockage / deadlock timeout
      vi.mocked(idb.openDB).mockRejectedValue(new Error("IDB Deadlock Upgrade Blocked"));

      const testKeys = { privateKey: "priv-123", publicKey: "pub-123" };
      await store.saveDeviceKeys(testKeys);

      expect(warnSpy.mock.calls[0][0]).toContain(
        "[charproof] IndexedDB failed to open. Falling back to in-memory store."
      );

      const loadedKeys = await store.loadDeviceKeys();
      expect(loadedKeys).toEqual(testKeys);

      warnSpy.mockRestore();
    });
  });

  describe("FirestoreLedgerEventStore - ZK Decoy Chaff", () => {
    it("should cache chaff pool IDs on success, and use them on network failure", async () => {
      const store = new FirestoreLedgerEventStore();
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      // 1. Success Path - Cache active poll IDs
      const mockSnapshot = {
        exists: () => true,
        data: () => ({ activePollIds: ["poll-a", "poll-b"] }),
      };
      vi.mocked(firestore.getDoc).mockResolvedValue(mockSnapshot as any);

      const batchMock = {
        set: vi.fn(),
        commit: vi.fn().mockResolvedValue(undefined),
      };
      vi.mocked(firestore.writeBatch).mockReturnValue(batchMock as any);

      // Use valid base64 payloads so decoy length/format can be compared.
      const realData = { encryptedData: btoa("a realistic ciphertext blob!!"), iv: btoa("123456789012") };
      await store.appendEvent("my-ledger", "event-123", realData);

      // Verify cached in localStorage
      expect(localStorage.getItem("charproof_chaff_pool")).toBe(JSON.stringify(["poll-a", "poll-b"]));

      // 1 real + 2 decoys (pool minus self) = 3 writes
      expect(batchMock.set).toHaveBeenCalledTimes(3);

      // 2. Failure Path - Fallback to cache
      vi.mocked(firestore.getDoc).mockRejectedValue(new Error("Network Down"));
      await store.appendEvent("my-ledger", "event-456", realData);
      expect(warnSpy.mock.calls[0][0]).toContain(
        "Failed to fetch chaff pool from network. Attempting local storage cache fallback..."
      );

      warnSpy.mockRestore();
    });

    it("produces decoys indistinguishable from real payloads (valid base64, matching length)", async () => {
      const store = new FirestoreLedgerEventStore({ decoyCount: 2 });

      vi.mocked(firestore.getDoc).mockResolvedValue({
        exists: () => true,
        data: () => ({ activePollIds: ["poll-a", "poll-b", "poll-c"] }),
      } as any);

      const batchMock = { set: vi.fn(), commit: vi.fn().mockResolvedValue(undefined) };
      vi.mocked(firestore.writeBatch).mockReturnValue(batchMock as any);

      const realData = { encryptedData: btoa("the genuine encrypted ciphertext payload"), iv: btoa("abcdefghijkl") };
      await store.appendEvent("real-ledger", "event-1", realData);

      const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
      const realEncLen = base64ToUint8(realData.encryptedData).length;
      const realIvLen = base64ToUint8(realData.iv).length;

      const decoyWrites = batchMock.set.mock.calls
        .map((call) => call[1])
        .filter((payload) => payload.eventId !== "event-1");

      expect(decoyWrites.length).toBe(2);
      for (const decoy of decoyWrites) {
        // Well-formed base64 with padding only at the end (the old generator failed this).
        expect(decoy.encryptedData).toMatch(base64Pattern);
        expect(decoy.iv).toMatch(base64Pattern);
        // Same decoded length as the real payload → identical on-disk footprint.
        expect(base64ToUint8(decoy.encryptedData).length).toBe(realEncLen);
        expect(base64ToUint8(decoy.iv).length).toBe(realIvLen);
        // Not a copy of the real ciphertext.
        expect(decoy.encryptedData).not.toBe(realData.encryptedData);
      }
    });

    it("should retry genesis event fetches on transient errors", async () => {
      const store = new FirestoreLedgerEventStore();
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      const transientError = new Error("Firestore Unavailable");
      (transientError as any).code = "unavailable";

      // Reject once with transient error, then succeed
      const mockDocs = {
        empty: false,
        docs: [{ data: () => ({ encryptedData: "genesis-enc", iv: "genesis-iv" }) }],
      };
      vi.mocked(firestore.getDocs)
        .mockRejectedValueOnce(transientError)
        .mockResolvedValueOnce(mockDocs as any);

      vi.useFakeTimers();
      const promise = store.getGenesisEvent("ledger-123");
      await vi.runAllTimersAsync();
      const res = await promise;

      expect(res).toEqual({ encryptedData: "genesis-enc", iv: "genesis-iv" });
      expect(warnSpy.mock.calls[0][0]).toContain(
        "[charproof] Transient error"
      );

      warnSpy.mockRestore();
      vi.useRealTimers();
    });
  });

  describe("FirestoreAccountKeyStore - Robust Retries", () => {
    it("should retry reads on transient error", async () => {
      const store = new FirestoreAccountKeyStore();
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      const transientError = new Error("Firestore Cancelled");
      (transientError as any).code = "cancelled";

      const mockSnapshot = {
        exists: () => true,
        data: () => ({ keyring: {} }),
      };

      vi.mocked(firestore.getDoc)
        .mockRejectedValueOnce(transientError)
        .mockResolvedValueOnce(mockSnapshot as any);

      vi.useFakeTimers();
      const promise = store.getKeystoreEntry("ledger-123");
      await vi.runAllTimersAsync();
      const res = await promise;

      expect(res).toEqual({ keyring: {} });
      expect(warnSpy.mock.calls[0][0]).toContain(
        "[charproof] Transient error"
      );

      warnSpy.mockRestore();
      vi.useRealTimers();
    });
  });

  describe("Keystore onError listener propagation", () => {
    it("should pass onError callbacks through subscribeToUserKeystore", () => {
      const mockOnError = vi.fn();
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      
      subscribeToUserKeystore(
        vi.fn(),
        mockOnError
      );

      const onSnapshotCalls = vi.mocked(firestore.onSnapshot).mock.calls;
      expect(onSnapshotCalls.length).toBe(1);
      const errorHandler = onSnapshotCalls[0][2];
      expect(errorHandler).toBeTypeOf("function");

      const testError = new Error("Firestore stream failed");
      errorHandler(testError);

      expect(mockOnError).toHaveBeenCalledWith(testError);
      errorSpy.mockRestore();
    });
  });
});
