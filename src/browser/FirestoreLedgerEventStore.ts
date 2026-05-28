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
  getDoc,
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

export class FirestoreLedgerEventStore implements LedgerEventStore {
  async appendEvent(ledgerId: string, eventId: string, data: { encryptedData: string; iv: string }): Promise<void> {
    const db = getDb();
    const batch = writeBatch(db);
    const X = 3; // Configurable number of decoy writes

    // 1. Queue the legitimate event write
    const realRef = doc(db, "polls", ledgerId, "events", eventId);
    batch.set(realRef, {
      eventId,
      createdAt: serverTimestamp(),
      encryptedData: data.encryptedData,
      iv: data.iv
    });

    try {
      // 2. Fetch the current chaff pool
      const poolSnap = await getDoc(doc(db, "chaff_pool", "current"));

      if (poolSnap.exists()) {
        const activePolls: string[] = poolSnap.data().activePollIds || [];
        
        // Exclude our own ledgerId to avoid writing self-chaff
        const candidates = activePolls.filter(id => id !== ledgerId);
        
        // Randomly select up to X candidate IDs
        const selectedChaffIds = candidates
          .sort(() => 0.5 - Math.random())
          .slice(0, X);

        // 3. Queue the decoy chaff writes
        for (const chaffId of selectedChaffIds) {
          const decoyEventId = generateId();
          const decoyRef = doc(db, "polls", chaffId, "events", decoyEventId);
          
          // Generate realistic decoy payload matching character lengths of original data
          const decoyPayload = generateRealisticDecoy(data.encryptedData.length, data.iv.length);
          
          batch.set(decoyRef, {
            eventId: decoyEventId,
            createdAt: serverTimestamp(),
            encryptedData: decoyPayload.encryptedData,
            iv: decoyPayload.iv
          });
        }
      }
    } catch (err) {
      // Silent catch: network failures fetching chaff must NEVER block user voting.
      console.warn("Failed to fetch chaff pool. Proceeding with single write.", err);
    }

    // 4. Commit all writes simultaneously in a single network request (with retry)
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
    const snapshot = await getDocs(q);
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
