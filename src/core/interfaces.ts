import type { AccountKeysDocument, KeystoreEntry, PendingDevice } from "./types";

// ─── Branding Utility ───────────────────────────────────────────────
declare const __brand: unique symbol;
/**
 * Branding helper to create compile-time type-safe semantic type wrappers.
 * Prevents developers from accidentally passing raw strings or buffers in place
 * of specific cryptographic handles.
 */
export type Brand<T, B extends string> = T & { readonly [__brand]: B };

// ─── Opaque Key Handles ─────────────────────────────────────────────
/** Symmetric AES-GCM 256-bit key handle. */
export type AesGcmKey          = Brand<CryptoKey, 'AesGcmKey'>;
/** Digital signature verification key handle (ECDSA). */
export type EcdsaPublicKey     = Brand<CryptoKey, 'EcdsaPublicKey'>;
/** Digital signature generation key handle (ECDSA). */
export type EcdsaPrivateKey    = Brand<CryptoKey, 'EcdsaPrivateKey'>;
/** Asymmetric key wrapping public key handle (RSA-OAEP). */
export type RsaOaepPublicKey   = Brand<CryptoKey, 'RsaOaepPublicKey'>;
/** Asymmetric key unwrapping private key handle (RSA-OAEP). */
export type RsaOaepPrivateKey  = Brand<CryptoKey, 'RsaOaepPrivateKey'>;
/** Password-derived symmetric AES key handle (PBKDF2). */
export type Pbkdf2DerivedKey   = Brand<CryptoKey, 'Pbkdf2DerivedKey'>;

/** Union of all supported cryptographic key handles. */
export type AnyKey = AesGcmKey | EcdsaPublicKey | EcdsaPrivateKey
                   | RsaOaepPublicKey | RsaOaepPrivateKey | Pbkdf2DerivedKey;

// ─── Semantic Byte Arrays ───────────────────────────────────────────
/** Raw bytes of a symmetric key. */
export type RawKeyBytes        = Brand<Uint8Array, 'RawKeyBytes'>;
/** Base64 or raw SPKI-encoded public key bytes. */
export type SpkiBytes          = Brand<Uint8Array, 'SpkiBytes'>;
/** Base64 or raw PKCS#8-encoded private key bytes. */
export type Pkcs8Bytes         = Brand<Uint8Array, 'Pkcs8Bytes'>;
/** Ciphertext payload bytes. */
export type CiphertextBytes    = Brand<Uint8Array, 'CiphertextBytes'>;
/** Initialization vector bytes for symmetric encryption. */
export type IvBytes            = Brand<Uint8Array, 'IvBytes'>;
/** Unencrypted plaintext data bytes. */
export type PlaintextBytes     = Brand<Uint8Array, 'PlaintextBytes'>;
/** Digital signature output bytes. */
export type SignatureBytes     = Brand<Uint8Array, 'SignatureBytes'>;
/** Hash digest output bytes. */
export type DigestBytes        = Brand<Uint8Array, 'DigestBytes'>;
/** Asymmetrically wrapped symmetric key bytes. */
export type WrappedKeyBytes    = Brand<Uint8Array, 'WrappedKeyBytes'>;

/**
 * Defines low-level cryptographic functions used by Charproof.
 * Allows injection of either the browser's native WebCrypto provider or test mocks.
 */
export interface CryptoProvider {
  /** Generates high-entropy random bytes. */
  getRandomBytes(length: number): Uint8Array;
  /** Generates a random v4 UUID string. */
  randomUUID(): string;

  /** Generates a symmetric AES-GCM key handle. */
  generateSymmetricKey(length?: 128 | 256): Promise<AesGcmKey>;
  /** Imports raw symmetric key bytes into an AES key handle. */
  importSymmetricKey(raw: RawKeyBytes): Promise<AesGcmKey>;
  /** Exports an AES key handle into raw bytes. */
  exportSymmetricKey(key: AesGcmKey): Promise<RawKeyBytes>;
  /** Encrypts plaintext bytes using AES-GCM. */
  encrypt(key: AesGcmKey | Pbkdf2DerivedKey, plaintext: PlaintextBytes): Promise<{ ciphertext: CiphertextBytes; iv: IvBytes }>;
  /** Decrypts ciphertext bytes using AES-GCM. */
  decrypt(key: AesGcmKey | Pbkdf2DerivedKey, ciphertext: CiphertextBytes, iv: IvBytes): Promise<PlaintextBytes>;

  /** Generates an ECDSA keypair for digital signing. */
  generateSigningKeyPair(): Promise<{ publicKey: EcdsaPublicKey; privateKey: EcdsaPrivateKey }>;
  /** Exports an ECDSA public key handle into SPKI bytes. */
  exportSigningPublicKey(key: EcdsaPublicKey): Promise<SpkiBytes>;
  /** Exports an ECDSA private key handle into PKCS#8 bytes. */
  exportSigningPrivateKey(key: EcdsaPrivateKey): Promise<Pkcs8Bytes>;
  /** Imports SPKI bytes into an ECDSA public key handle. */
  importSigningPublicKey(spki: SpkiBytes): Promise<EcdsaPublicKey>;
  /** Imports PKCS#8 bytes into an ECDSA private key handle. */
  importSigningPrivateKey(pkcs8: Pkcs8Bytes): Promise<EcdsaPrivateKey>;
  /** Signs data using an ECDSA private key. */
  sign(privateKey: EcdsaPrivateKey, data: PlaintextBytes): Promise<SignatureBytes>;
  /** Verifies a signature against data using an ECDSA public key. */
  verify(publicKey: EcdsaPublicKey, signature: SignatureBytes, data: PlaintextBytes): Promise<boolean>;

  /** Generates an RSA keypair for key wrapping. */
  generateDeviceKeyPair(): Promise<{ publicKey: RsaOaepPublicKey; privateKey: RsaOaepPrivateKey }>;
  /** Exports an RSA public key handle into SPKI bytes. */
  exportDevicePublicKey(key: RsaOaepPublicKey): Promise<SpkiBytes>;
  /** Exports an RSA private key handle into PKCS#8 bytes. */
  exportDevicePrivateKey(key: RsaOaepPrivateKey): Promise<Pkcs8Bytes>;
  /** Imports SPKI bytes into an RSA public key handle. */
  importDevicePublicKey(spki: SpkiBytes): Promise<RsaOaepPublicKey>;
  /** Imports PKCS#8 bytes into an RSA private key handle. */
  importDevicePrivateKey(pkcs8: Pkcs8Bytes): Promise<RsaOaepPrivateKey>;
  /** Wraps/encrypts an AES key using an RSA public key. */
  wrapKey(wrappingKey: RsaOaepPublicKey, keyToWrap: AesGcmKey): Promise<WrappedKeyBytes>;
  /** Unwraps/decrypts an AES key using an RSA private key. */
  unwrapKey(unwrappingKey: RsaOaepPrivateKey, wrappedKey: WrappedKeyBytes): Promise<AesGcmKey>;

  /** Derives a symmetric key from a password and salt using PBKDF2. */
  deriveKeyFromPassword(password: PlaintextBytes, salt: PlaintextBytes, iterations: number): Promise<Pbkdf2DerivedKey>;

  /** Computes the cryptographic hash of data. */
  digest(algorithm: 'SHA-256', data: Uint8Array): Promise<DigestBytes>;
}

/**
 * Storage adapter interface for the user's remote Account Keystore (typically Cloud Firestore).
 */
export interface AccountKeyStore {
  /** Retrieves the root account keys document. */
  getAccountKeys(): Promise<AccountKeysDocument | null>;

  /**
   * Performs an atomic database transaction on the account keys document.
   * Ensures safe concurrency during device authorizations or rotations.
   */
  transactAccountKeys(
    updater: (current: AccountKeysDocument) => AccountKeysDocument | Promise<AccountKeysDocument>
  ): Promise<void>;

  /** Directly overwrites the root account keys document (used during genesis initialization). */
  setAccountKeys(doc: AccountKeysDocument): Promise<void>;

  /** Retrieves a wrapped ledger symmetric key from the keystore. */
  getKeystoreEntry(ledgerId: string): Promise<KeystoreEntry | null>;

  /** Saves a wrapped ledger symmetric key in the keystore. */
  setKeystoreEntry(ledgerId: string, entry: KeystoreEntry): Promise<void>;

  /** Archives or unarchives a ledger keystore entry. */
  setKeystoreArchivedStatus(docId: string, isArchived: boolean): Promise<void>;

  /** Retrieves a pending enrollment request for a device. */
  getPendingDevice(deviceId: string): Promise<PendingDevice | null>;

  /** Registers a pending enrollment request for a device. */
  setPendingDevice(deviceId: string, data: PendingDevice): Promise<void>;

  /** Atomically updates the root account keyring and changes a pending device status. */
  transactApproveDevice(
    accountUpdater: (current: AccountKeysDocument) => AccountKeysDocument | Promise<AccountKeysDocument>,
    pendingDeviceId: string,
    pendingUpdate: Partial<PendingDevice>
  ): Promise<void>;

  /** Listens to live, real-time updates of pending device enrollment requests. */
  subscribePendingDevices(onSnapshot: (devices: PendingDevice[]) => void): () => void;

  /** Listens to live updates of a specific pending device request. */
  subscribePendingDevice(deviceId: string, onSnapshot: (device: PendingDevice | null) => void): () => void;

  /** Listens to real-time changes to the root account keys document. */
  subscribeAccountKeys(onSnapshot: (doc: AccountKeysDocument | null) => void): () => void;

  /** Listens to real-time changes of all user keystore entries. */
  subscribeKeystore(onSnapshot: (entries: KeystoreEntry[]) => void): () => void;

  /** Deletes a registered pending device request. */
  deletePendingDevice(deviceId: string): Promise<void>;

  /** Destroys all remote zero-knowledge keys, entries, and documents (GDPR/purge flow). */
  resetRemoteStore(): Promise<void>;
}

/**
 * Storage adapter interface for the client-side encrypted transaction logs.
 */
export interface LedgerEventStore {
  /** Writes an encrypted event to the remote database. */
  appendEvent(ledgerId: string, eventId: string, data: { encryptedData: string; iv: string }): Promise<void>;

  /** Listens to real-time updates of all events in the ledger, maintaining strict write ordering. */
  subscribe(
    ledgerId: string,
    onSnapshot: (events: Array<{ encryptedData: string; iv: string; id: string }>) => void
  ): () => void;

  /** Retrieves the very first genesis event in the ledger. */
  getGenesisEvent(ledgerId: string): Promise<{ encryptedData: string; iv: string } | null>;

  /** Creates a new, initialized ledger document entry in the remote database. */
  createLedger(ledgerId: string): Promise<void>;
}

/**
 * Interface for the client-side persistent storage of device secrets and identities
 * (typically implemented using browser IndexedDB and localStorage).
 */
export interface LocalDeviceStore {
  /** Returns the locally generated unique ID of this device. */
  getDeviceId(): string;
  /** Returns the local human-readable display name of this device. */
  getDeviceName(): string;
  /** Sets the local human-readable display name of this device. */
  setDeviceName(name: string): void;

  /** Persists the device's asymmetric RSA key pair locally. */
  saveDeviceKeys(keys: { privateKey: string; publicKey: string }): Promise<void>;
  /** Loads the persistent asymmetric RSA key pair of the device. */
  loadDeviceKeys(): Promise<{ privateKey: string; publicKey: string } | null>;

  /** Persists the derived Account Master Key locally (cached session credentials). */
  saveMasterKey(uid: string, key: AesGcmKey): Promise<void>;
  /** Loads the cached Account Master Key. */
  loadMasterKey(uid: string): Promise<AesGcmKey | null>;

  /** Persists a specific ledger's signing identity locally. */
  saveIdentity(ledgerId: string, keys: { privateKey: string; publicKey: string }): Promise<void>;
  /** Loads a persistent ledger's signing identity. */
  loadIdentity(ledgerId: string): Promise<{ privateKey: string; publicKey: string } | null>;

  /** Retrieves the persistent WebAuthn PRF credential ID associated with the user account. */
  getPrfCredentialId(uid: string): string | null;
  /** Persists the WebAuthn PRF credential ID. */
  setPrfCredentialId(uid: string, credentialId: string): void;

  /** Wipes all locally cached secrets, keys, and identities. */
  clearAll(): Promise<void>;
}

/**
 * Authentication Provider interface allowing Charproof to query the user's active login state.
 */
export interface AuthProvider {
  /** Returns the current authenticated user's details, or null if signed out. */
  getCurrentUser(): { uid: string; isAnonymous: boolean; email?: string; displayName?: string } | null;
}

/**
 * WebAuthn Credential Provider interface to perform hardware-backed key derivation.
 */
export interface PrfProvider {
  /** Generates a new hardware credential and derives a high-entropy key from the authenticator. */
  createCredential(
    userId: string,
    userName: string,
    displayName: string
  ): Promise<{ credentialId: string; prfResult: Uint8Array }>;
  
  /** Retrieves a derived key using existing WebAuthn credential IDs. */
  getAssertion(
    credentialIds: string[]
  ): Promise<{ usedCredentialId: string; prfResult: Uint8Array }>;
}
