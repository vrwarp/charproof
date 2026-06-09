import { vi, describe, it, expect, beforeEach } from "vitest";
import { BrowserLocalDeviceStore } from "../../browser/BrowserLocalDeviceStore";
import { FirestoreAccountKeyStore } from "../../browser/FirestoreAccountKeyStore";
import { FirestoreLedgerEventStore } from "../../browser/FirestoreLedgerEventStore";
import { subscribeToUserKeystore } from "../../deviceService";
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

  describe("FirestoreLedgerEventStore - Tenant-Local Decoy Chaff", () => {
    it("writes only the real event when no decoy pool is configured", async () => {
      const store = new FirestoreLedgerEventStore();

      const batchMock = {
        set: vi.fn(),
        commit: vi.fn().mockResolvedValue(undefined),
      };
      vi.mocked(firestore.writeBatch).mockReturnValue(batchMock as any);

      await store.appendEvent("my-ledger", "event-123", { encryptedData: "enc", iv: "iv" });

      // Exactly one write (the real event) — no decoys, no cross-tenant writes.
      expect(batchMock.set).toHaveBeenCalledTimes(1);
      expect(batchMock.commit).toHaveBeenCalledTimes(1);
      // It must NOT read any global chaff pool document.
      expect(firestore.getDoc).not.toHaveBeenCalled();
    });

    it("writes decoys only into the user's own configured ledgers, never foreign ones", async () => {
      const store = new FirestoreLedgerEventStore({ decoyPool: ["mine-a", "mine-b", "mine-c"], decoyCount: 2 });

      const batchMock = {
        set: vi.fn(),
        commit: vi.fn().mockResolvedValue(undefined),
      };
      vi.mocked(firestore.writeBatch).mockReturnValue(batchMock as any);

      // Track which (collection) paths were targeted via the doc() mock.
      vi.mocked(firestore.doc).mockImplementation((...args: any[]) => ({ path: args.join("/") }) as any);

      await store.appendEvent("mine-a", "event-123", { encryptedData: "enc", iv: "iv" });

      // 1 real + 2 decoys = 3 writes.
      expect(batchMock.set).toHaveBeenCalledTimes(3);

      // Every targeted ledger must be one of the user's own ledgers — never a foreign poll.
      const targetedLedgers = batchMock.set.mock.calls.map((call) => {
        const path: string = call[0].path; // e.g. "<db>/polls/<ledgerId>/events/<eventId>"
        const m = path.match(/polls\/([^/]+)\/events/);
        return m ? m[1] : null;
      });
      for (const ledger of targetedLedgers) {
        expect(["mine-a", "mine-b", "mine-c"]).toContain(ledger);
      }
      // The decoys must not target the real ledger itself.
      const decoyLedgers = targetedLedgers.filter((l) => l !== "mine-a");
      expect(decoyLedgers.length).toBe(2);
      for (const ledger of decoyLedgers) {
        expect(["mine-b", "mine-c"]).toContain(ledger);
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
