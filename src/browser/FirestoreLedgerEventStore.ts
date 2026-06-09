import {
  collection,
  doc,
  setDoc,
  onSnapshot,
  query,
  orderBy,
  getDocs,
  limit,
  serverTimestamp,
  writeBatch
} from "firebase/firestore";
import { getDb } from "../config";
import type { LedgerEventStore } from "../core/interfaces";
import { withRetry } from "../core/retry";

function generateId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return Math.random().toString(36).substring(2, 15);
}

function generateRealisticDecoy(encLength: number, ivLength: number): { encryptedData: string; iv: string } {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  let encryptedData = "";
  let iv = "";
  for (let i = 0; i < encLength; i++) {
    encryptedData += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  for (let i = 0; i < ivLength; i++) {
    iv += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return { encryptedData, iv };
}

export interface LedgerEventStoreOptions {
  /**
   * Ledger IDs that belong to THIS user and that this user is permitted to write
   * to. When non-empty, each real write is accompanied by decoy writes into a
   * random subset of these ledgers, hiding which ledger actually changed.
   *
   * IMPORTANT: only the caller's own ledgers may appear here. The previous
   * implementation pulled a global cross-tenant pool and wrote decoys into other
   * users' ledgers, which both leaked the set of active ledgers and required
   * security rules permitting any user to write to any ledger. Decoys are now
   * strictly tenant-local and opt-in.
   */
  decoyPool?: string[];
  /** Number of decoy writes per real write. Default: 3. */
  decoyCount?: number;
}

export class FirestoreLedgerEventStore implements LedgerEventStore {
  private decoyPool: string[];
  private readonly decoyCount: number;

  constructor(options?: LedgerEventStoreOptions) {
    this.decoyPool = options?.decoyPool ? [...options.decoyPool] : [];
    this.decoyCount = options?.decoyCount ?? 3;
  }

  /** Updates the set of the user's own ledgers eligible to receive decoy writes. */
  setDecoyPool(ledgerIds: string[]): void {
    this.decoyPool = [...ledgerIds];
  }

  async appendEvent(ledgerId: string, eventId: string, data: { encryptedData: string; iv: string }): Promise<void> {
    const db = getDb();
    const batch = writeBatch(db);

    // 1. The legitimate event write.
    const realRef = doc(db, "polls", ledgerId, "events", eventId);
    batch.set(realRef, {
      eventId,
      createdAt: serverTimestamp(),
      encryptedData: data.encryptedData,
      iv: data.iv
    });

    // 2. Tenant-local decoy writes (only into the user's own registered ledgers).
    //    Built once, so a transient-error retry replays the same batch (idempotent).
    const candidates = this.decoyPool.filter(id => id !== ledgerId);
    if (candidates.length > 0 && this.decoyCount > 0) {
      const selected = candidates
        .slice()
        .sort(() => 0.5 - Math.random())
        .slice(0, this.decoyCount);

      for (const chaffId of selected) {
        const decoyEventId = generateId();
        const decoyRef = doc(db, "polls", chaffId, "events", decoyEventId);
        const decoyPayload = generateRealisticDecoy(data.encryptedData.length, data.iv.length);
        batch.set(decoyRef, {
          eventId: decoyEventId,
          createdAt: serverTimestamp(),
          encryptedData: decoyPayload.encryptedData,
          iv: decoyPayload.iv
        });
      }
    }

    // 3. Commit all writes atomically (with transient-error retry).
    await withRetry(() => batch.commit());
  }

  subscribe(
    ledgerId: string,
    onUpdate: (events: Array<{ encryptedData: string; iv: string; id: string }>) => void,
    onError?: (error: Error) => void
  ): () => void {
    const eventsRef = collection(getDb(), "polls", ledgerId, "events");
    const q = query(eventsRef, orderBy("createdAt", "asc"));
    return onSnapshot(q,
      (snapshot) => {
        const events = snapshot.docs.map(docSnap => {
          const data = docSnap.data();
          return {
            id: docSnap.id,
            encryptedData: data.encryptedData,
            iv: data.iv
          };
        });
        onUpdate(events);
      },
      (error) => {
        console.error("[charproof] Ledger event listener error:", error);
        onError?.(error);
      }
    );
  }

  async getGenesisEvent(ledgerId: string): Promise<{ encryptedData: string; iv: string } | null> {
    const eventsRef = collection(getDb(), "polls", ledgerId, "events");
    const q = query(eventsRef, orderBy("createdAt", "asc"), limit(1));
    const snapshot = await withRetry(() => getDocs(q));
    if (snapshot.empty) return null;
    const data = snapshot.docs[0].data();
    return {
      encryptedData: data.encryptedData,
      iv: data.iv
    };
  }

  async createLedger(ledgerId: string): Promise<void> {
    const ref = doc(getDb(), "polls", ledgerId);
    await withRetry(() => setDoc(ref, {
      pollId: ledgerId,
      createdAt: serverTimestamp()
    }));
  }
}
