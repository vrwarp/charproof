import {
  collection,
  doc,
  setDoc,
  onSnapshot,
  query,
  orderBy,
  getDocs,
  getDoc,
  limit,
  serverTimestamp,
  writeBatch
} from "firebase/firestore";
import { getDb } from "../config";
import type { LedgerEventStore } from "../core/interfaces";
import { withRetry } from "../core/retry";
import { base64ToUint8, uint8ToBase64 } from "../core/base64";

const CHAFF_POOL_CACHE_KEY = "charproof_chaff_pool";

function generateId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return Math.random().toString(36).substring(2, 15);
}

function getRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}

/**
 * Produces a decoy payload that is byte-for-byte indistinguishable from a real
 * AES-GCM payload: cryptographically-random bytes, base64-encoded, with the SAME
 * decoded length (hence identical encoded length and padding) as the real one.
 *
 * This matters for plausible deniability — the previous implementation sampled
 * uniform characters from the base64 alphabet (with `=` at arbitrary positions),
 * which a snapshot adversary could trivially classify and discard as malformed,
 * collapsing the deniability the chaff is supposed to provide.
 */
function generateIndistinguishableDecoy(
  realEncryptedData: string,
  realIv: string
): { encryptedData: string; iv: string } {
  const encLen = base64ToUint8(realEncryptedData).length;
  const ivLen = base64ToUint8(realIv).length;
  return {
    encryptedData: uint8ToBase64(getRandomBytes(encLen)),
    iv: uint8ToBase64(getRandomBytes(ivLen))
  };
}

export class FirestoreLedgerEventStore implements LedgerEventStore {
  private readonly decoyCount: number;

  constructor(options?: { decoyCount?: number }) {
    this.decoyCount = options?.decoyCount ?? 3;
  }

  async appendEvent(ledgerId: string, eventId: string, data: { encryptedData: string; iv: string }): Promise<void> {
    const db = getDb();
    const batch = writeBatch(db);

    // 1. Queue the legitimate event write.
    const realRef = doc(db, "polls", ledgerId, "events", eventId);
    batch.set(realRef, {
      eventId,
      createdAt: serverTimestamp(),
      encryptedData: data.encryptedData,
      iv: data.iv
    });

    // 2. Add decoy writes into OTHER active ledgers, masking both which ledger
    //    really changed and its event count/timing. The pool of active ledger
    //    IDs is maintained server-side (a scheduled function); clients only read
    //    it. Decoy payloads are indistinguishable from real ciphertext.
    let activePolls: string[] = [];
    try {
      const poolSnap = await getDoc(doc(db, "chaff_pool", "current"));
      if (poolSnap.exists()) {
        activePolls = poolSnap.data().activePollIds || [];
        try {
          localStorage.setItem(CHAFF_POOL_CACHE_KEY, JSON.stringify(activePolls));
        } catch (e) {
          // Private browsing / storage full — non-fatal.
        }
      }
    } catch (err) {
      // Network failure — fall back to the last cached pool so chaff still flows.
      console.warn("Failed to fetch chaff pool from network. Attempting local storage cache fallback...", err);
      try {
        const cached = localStorage.getItem(CHAFF_POOL_CACHE_KEY);
        if (cached) activePolls = JSON.parse(cached) || [];
      } catch (cacheErr) {
        console.error("Local chaff pool cache fallback failed:", cacheErr);
      }
    }

    // The decoys are added to the batch ONCE, before commit, so a transient-error
    // retry replays the same batch rather than spraying fresh decoys each attempt.
    const candidates = activePolls.filter(id => id !== ledgerId);
    if (candidates.length > 0 && this.decoyCount > 0) {
      const selected = candidates
        .slice()
        .sort(() => 0.5 - Math.random())
        .slice(0, this.decoyCount);

      for (const chaffId of selected) {
        const decoyEventId = generateId();
        const decoyRef = doc(db, "polls", chaffId, "events", decoyEventId);
        const decoyPayload = generateIndistinguishableDecoy(data.encryptedData, data.iv);
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
