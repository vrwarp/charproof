import {
  importSymmetricKey,
  importPrivateKey,
  importPublicKey,
  exportSymmetricKey,
  exportPrivateKey,
  exportPublicKey,
  deriveKeyFromPassword,
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

export class DefaultLedgerSession implements LedgerSession {
  private pendingOwnerRecovery: EncryptedData | null;

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

  subscribe(onUpdate: (events: DecryptedLedgerEvent[]) => void): () => void {
    return eventStore.subscribe(this.ledgerId, async (rawEvents) => {
      const events = await processLedgerEventSnapshot(rawEvents, this.symmetricKey);
      onUpdate(events);
    });
  }

  async getGenesisEvent(): Promise<DecryptedLedgerEvent | null> {
    for (let i = 0; i < 10; i++) {
      const genesis = await eventStore.getGenesisEvent(this.ledgerId);
      if (genesis) {
        const decrypted = await decryptAndValidateEvent(
          genesis.encryptedData,
          genesis.iv,
          this.symmetricKey
        );
        if (decrypted) return decrypted;
      }
      await new Promise(r => setTimeout(r, 200));
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
    for (let i = 0; i < 10; i++) {
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
      await new Promise(r => setTimeout(r, 200));
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
