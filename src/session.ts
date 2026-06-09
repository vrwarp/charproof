import {
  importSymmetricKey,
  importPrivateKey,
  importPublicKey,
  exportSymmetricKey,
  exportPrivateKey,
  exportPublicKey,
  generateIdentityKeyPair
} from "./core/crypto";
import {
  prepareAppendEventEnvelope,
  decryptAndValidateEvent,
  processLedgerEventSnapshot,
  prepareGenesisCredentials,
  attemptRecoveryWithToken
} from "./core/sessionLogic";
import type {
  EncryptedData,
  LedgerSession,
  DecryptedLedgerEvent,
  LedgerCredentials,
  CreateLedgerResult
} from "./core/types";
import { saveToKeystore, loadFromKeystore } from "./deviceService";

import type { AesGcmKey, EcdsaPrivateKey, EcdsaPublicKey, LedgerEventStore, AccountKeyStore, LocalDeviceStore, AuthProvider } from "./core/interfaces";
import { FirestoreLedgerEventStore } from "./browser/FirestoreLedgerEventStore";
import { FirestoreAccountKeyStore } from "./browser/FirestoreAccountKeyStore";
import { BrowserLocalDeviceStore } from "./browser/BrowserLocalDeviceStore";
import { FirebaseAuthProvider } from "./browser/FirebaseAuthProvider";

let eventStore: LedgerEventStore = new FirestoreLedgerEventStore();
let keyStore: AccountKeyStore = new FirestoreAccountKeyStore();
let local: LocalDeviceStore = new BrowserLocalDeviceStore();
let auth: AuthProvider = new FirebaseAuthProvider();

export function setSessionProviders(providers: {
  ledgerEventStore?: LedgerEventStore;
  accountKeyStore?: AccountKeyStore;
  localDeviceStore?: LocalDeviceStore;
  authProvider?: AuthProvider;
}) {
  if (providers.ledgerEventStore) eventStore = providers.ledgerEventStore;
  if (providers.accountKeyStore) keyStore = providers.accountKeyStore;
  if (providers.localDeviceStore) local = providers.localDeviceStore;
  if (providers.authProvider) auth = providers.authProvider;
}

function generateId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return Math.random().toString(36).substring(2, 15);
}

/**
 * Configures the set of the user's OWN ledger IDs eligible to receive decoy
 * (chaff) writes, hiding which ledger actually changed. Only the caller's own
 * writable ledgers may be passed — decoys are never written cross-tenant.
 * No-op if the active event store does not support decoys.
 */
export function setLedgerDecoyPool(ledgerIds: string[]): void {
  const maybe = eventStore as { setDecoyPool?: (ids: string[]) => void };
  if (typeof maybe.setDecoyPool === "function") {
    maybe.setDecoyPool(ledgerIds);
  }
}

export class DefaultLedgerSession implements LedgerSession {
  private pendingOwnerRecovery: EncryptedData | null;

  /**
   * Optional allowlist of base64 SPKI signer public keys permitted to author
   * events on this ledger. When set, events whose embedded public key is not in
   * the set are rejected during validation, preventing a participant who holds
   * the shared symmetric key from impersonating another participant. When null,
   * any well-signed event is accepted (single-writer / trust-all mode).
   */
  private authorizedSigners: Set<string> | null = null;

  /** Per-session memoization of decrypted events keyed by id+iv to avoid
   *  re-decrypting the entire ledger on every snapshot. */
  private readonly eventCache: Map<string, DecryptedLedgerEvent | null> = new Map();

  constructor(
    private ledgerId: string,
    private symmetricKey: AesGcmKey,
    private signingPrivateKey: EcdsaPrivateKey,
    private signingPublicKey: EcdsaPublicKey,
    private symmetricKeyB64: string,
    private signingPublicKeyB64: string,
    ownerRecovery: EncryptedData | null = null
  ) {
    this.pendingOwnerRecovery = ownerRecovery;
  }

  /**
   * Restricts which signer public keys are accepted on this ledger. Pass the set
   * of authorized participant public keys (e.g. derived from membership events).
   * Production multi-writer ledgers SHOULD call this; see SECURITY.md.
   */
  setAuthorizedSigners(signers: Iterable<string> | null): void {
    this.authorizedSigners = signers ? new Set(signers) : null;
    // Membership changed: drop memoized validations so they are re-evaluated.
    this.eventCache.clear();
  }

  async appendEvent(action: any): Promise<void> {
    const encrypted = await prepareAppendEventEnvelope(
      this.signingPrivateKey,
      this.signingPublicKeyB64,
      action,
      this.symmetricKey,
      this.pendingOwnerRecovery
    );
    this.pendingOwnerRecovery = null;

    const eventId = generateId();
    await eventStore.appendEvent(this.ledgerId, eventId, encrypted);
  }

  subscribe(
    onUpdate: (events: DecryptedLedgerEvent[]) => void,
    onError?: (error: Error) => void
  ): () => void {
    return eventStore.subscribe(this.ledgerId, async (rawEvents) => {
      try {
        const events = await processLedgerEventSnapshot(
          rawEvents,
          this.symmetricKey,
          { authorizedSigners: this.authorizedSigners, cache: this.eventCache }
        );
        onUpdate(events);
      } catch (err: any) {
        // The async snapshot handler can reject independently of the underlying
        // listener; surface it to the caller instead of swallowing it.
        console.error("[charproof] Failed to process ledger snapshot:", err);
        onError?.(err);
      }
    }, onError);
  }

  async getGenesisEvent(): Promise<DecryptedLedgerEvent | null> {
    const maxAttempts = 10;
    let delay = 200;
    for (let i = 0; i < maxAttempts; i++) {
      try {
        const genesis = await eventStore.getGenesisEvent(this.ledgerId);
        if (genesis) {
          const decrypted = await decryptAndValidateEvent(
            genesis.encryptedData,
            genesis.iv,
            this.symmetricKey
          );
          if (decrypted) return decrypted;
        }
      } catch (e: any) {
        // On network errors, let the backoff handle it; on permanent errors, throw immediately
        const isTransient = e.code === 'unavailable' || e.code === 'deadline-exceeded' || e.code === 'resource-exhausted';
        if (!isTransient && i >= 2) throw e; // Give non-transient errors a couple tries for eventual consistency
      }
      await new Promise(r => setTimeout(r, delay));
      delay = Math.min(delay * 1.5, 2000); // Exponential backoff, capped at 2s
    }
    return null;
  }

  exportSessionKey(): string {
    return this.symmetricKeyB64;
  }

  getSignerPublicKey(): string {
    return this.signingPublicKeyB64;
  }
}

export async function createLedgerSession(): Promise<CreateLedgerResult> {
  const ledgerId = generateId();
  const material = await prepareGenesisCredentials();

  const user = auth.getCurrentUser();
  if (user && !user.isAnonymous) {
    await saveToKeystore(ledgerId, material.creds);
  } else {
    await local.saveIdentity(ledgerId, {
      privateKey: material.creds.signingPrivateKey,
      publicKey: material.creds.signingPublicKey
    });
  }

  await eventStore.createLedger(ledgerId);

  const session = new DefaultLedgerSession(
    ledgerId,
    material.symmetricKey,
    material.signingPrivateKey,
    material.signingPublicKey,
    material.creds.symmetricKey,
    material.creds.signingPublicKey,
    material.ownerRecovery
  );

  return { session, ownershipToken: material.ownershipToken, ledgerId };
}

export async function getLedgerSession(
  ledgerId: string,
  options?: { shareableKey?: string; ownershipToken?: string }
): Promise<LedgerSession> {
  const user = auth.getCurrentUser();

  // 1. Try Firestore keystore
  if (user && !user.isAnonymous) {
    const creds = await loadFromKeystore(ledgerId);
    if (creds) {
      return new DefaultLedgerSession(
        ledgerId,
        await importSymmetricKey(creds.symmetricKey),
        await importPrivateKey(creds.signingPrivateKey),
        await importPublicKey(creds.signingPublicKey),
        creds.symmetricKey,
        creds.signingPublicKey
      );
    }
  }

  // 2. Try Local device store (IndexedDB)
  const stored = await local.loadIdentity(ledgerId);
  if (stored && options?.shareableKey) {
    if (user && !user.isAnonymous) {
      try {
        const cloudCreds = await loadFromKeystore(ledgerId);
        if (!cloudCreds) {
          console.log(`Syncing local identity for ledger ${ledgerId} to cloud keystore`);
          const creds: LedgerCredentials = {
            symmetricKey: options.shareableKey,
            signingPrivateKey: stored.privateKey,
            signingPublicKey: stored.publicKey
          };
          await saveToKeystore(ledgerId, creds);
        }
      } catch (err) {
        console.warn("Failed to sync local identity to cloud keystore:", err);
      }
    }
    return new DefaultLedgerSession(
      ledgerId,
      await importSymmetricKey(options.shareableKey),
      await importPrivateKey(stored.privateKey),
      await importPublicKey(stored.publicKey),
      options.shareableKey,
      stored.publicKey
    );
  }

  // 3. Ownership token recovery
  if (options?.ownershipToken && options?.shareableKey) {
    let delay = 200;
    for (let i = 0; i < 10; i++) {
      try {
        const genesis = await eventStore.getGenesisEvent(ledgerId);
        if (genesis) {
          const creds = await attemptRecoveryWithToken(
            options.ownershipToken,
            options.shareableKey,
            genesis
          );
          if (creds) {
            if (user && !user.isAnonymous) {
              await saveToKeystore(ledgerId, creds);
            } else {
              await local.saveIdentity(ledgerId, {
                privateKey: creds.signingPrivateKey,
                publicKey: creds.signingPublicKey
              });
            }
            return new DefaultLedgerSession(
              ledgerId,
              await importSymmetricKey(options.shareableKey),
              await importPrivateKey(creds.signingPrivateKey),
              await importPublicKey(creds.signingPublicKey),
              options.shareableKey,
              creds.signingPublicKey
            );
          }
        }
      } catch (e: any) {
        const isTransient = e.code === 'unavailable' || e.code === 'deadline-exceeded' || e.code === 'resource-exhausted';
        if (!isTransient && i >= 2) throw e;
      }
      await new Promise(r => setTimeout(r, delay));
      delay = Math.min(delay * 1.5, 2000);
    }
  }

  // 4. New participant
  if (options?.shareableKey) {
    const keyPair = await generateIdentityKeyPair();
    const privB64 = await exportPrivateKey(keyPair.privateKey);
    const pubB64 = await exportPublicKey(keyPair.publicKey);

    await local.saveIdentity(ledgerId, { privateKey: privB64, publicKey: pubB64 });

    if (user && !user.isAnonymous) {
      const creds: LedgerCredentials = {
        symmetricKey: options.shareableKey,
        signingPrivateKey: privB64,
        signingPublicKey: pubB64
      };
      await saveToKeystore(ledgerId, creds);
    }

    return new DefaultLedgerSession(
      ledgerId,
      await importSymmetricKey(options.shareableKey),
      keyPair.privateKey,
      keyPair.publicKey,
      options.shareableKey,
      pubB64
    );
  }

  throw new Error("Access Denied: No credentials found and no shareable key provided.");
}
