import type { AccountKeysDocument, KeystoreEntry, PendingDevice } from "./types";

// ─── Branding Utility ───────────────────────────────────────────────
declare const __brand: unique symbol;
export type Brand<T, B extends string> = T & { readonly [__brand]: B };

// ─── Opaque Key Handles ─────────────────────────────────────────────
export type AesGcmKey          = Brand<CryptoKey, 'AesGcmKey'>;          // Symmetric encryption/decryption
export type EcdsaPublicKey     = Brand<CryptoKey, 'EcdsaPublicKey'>;     // Signature verification
export type EcdsaPrivateKey    = Brand<CryptoKey, 'EcdsaPrivateKey'>;    // Signing
export type RsaOaepPublicKey   = Brand<CryptoKey, 'RsaOaepPublicKey'>;   // Key wrapping
export type RsaOaepPrivateKey  = Brand<CryptoKey, 'RsaOaepPrivateKey'>;  // Key unwrapping
export type Pbkdf2DerivedKey   = Brand<CryptoKey, 'Pbkdf2DerivedKey'>;   // Password-derived AES key

export type AnyKey = AesGcmKey | EcdsaPublicKey | EcdsaPrivateKey
                   | RsaOaepPublicKey | RsaOaepPrivateKey | Pbkdf2DerivedKey;

// ─── Semantic Byte Arrays ───────────────────────────────────────────
export type RawKeyBytes        = Brand<Uint8Array, 'RawKeyBytes'>;        // Raw symmetric key material
export type SpkiBytes          = Brand<Uint8Array, 'SpkiBytes'>;          // SubjectPublicKeyInfo encoding
export type Pkcs8Bytes         = Brand<Uint8Array, 'Pkcs8Bytes'>;         // PKCS#8 private key encoding
export type CiphertextBytes    = Brand<Uint8Array, 'CiphertextBytes'>;    // Encrypted data
export type IvBytes            = Brand<Uint8Array, 'IvBytes'>;            // Initialization vector
export type PlaintextBytes     = Brand<Uint8Array, 'PlaintextBytes'>;     // Plaintext data
export type SignatureBytes     = Brand<Uint8Array, 'SignatureBytes'>;     // Digital signature
export type DigestBytes        = Brand<Uint8Array, 'DigestBytes'>;        // Hash output
export type WrappedKeyBytes    = Brand<Uint8Array, 'WrappedKeyBytes'>;    // RSA-OAEP wrapped key

export interface CryptoProvider {
  // Random
  getRandomBytes(length: number): Uint8Array;
  randomUUID(): string;

  // AES-GCM
  generateSymmetricKey(length?: 128 | 256): Promise<AesGcmKey>;
  importSymmetricKey(raw: RawKeyBytes): Promise<AesGcmKey>;
  exportSymmetricKey(key: AesGcmKey): Promise<RawKeyBytes>;
  encrypt(key: AesGcmKey | Pbkdf2DerivedKey, plaintext: PlaintextBytes): Promise<{ ciphertext: CiphertextBytes; iv: IvBytes }>;
  decrypt(key: AesGcmKey | Pbkdf2DerivedKey, ciphertext: CiphertextBytes, iv: IvBytes): Promise<PlaintextBytes>;

  // ECDSA
  generateSigningKeyPair(): Promise<{ publicKey: EcdsaPublicKey; privateKey: EcdsaPrivateKey }>;
  exportSigningPublicKey(key: EcdsaPublicKey): Promise<SpkiBytes>;
  exportSigningPrivateKey(key: EcdsaPrivateKey): Promise<Pkcs8Bytes>;
  importSigningPublicKey(spki: SpkiBytes): Promise<EcdsaPublicKey>;
  importSigningPrivateKey(pkcs8: Pkcs8Bytes): Promise<EcdsaPrivateKey>;
  sign(privateKey: EcdsaPrivateKey, data: PlaintextBytes): Promise<SignatureBytes>;
  verify(publicKey: EcdsaPublicKey, signature: SignatureBytes, data: PlaintextBytes): Promise<boolean>;

  // RSA-OAEP (device keys)
  generateDeviceKeyPair(): Promise<{ publicKey: RsaOaepPublicKey; privateKey: RsaOaepPrivateKey }>;
  exportDevicePublicKey(key: RsaOaepPublicKey): Promise<SpkiBytes>;
  exportDevicePrivateKey(key: RsaOaepPrivateKey): Promise<Pkcs8Bytes>;
  importDevicePublicKey(spki: SpkiBytes): Promise<RsaOaepPublicKey>;
  importDevicePrivateKey(pkcs8: Pkcs8Bytes): Promise<RsaOaepPrivateKey>;
  wrapKey(wrappingKey: RsaOaepPublicKey, keyToWrap: AesGcmKey): Promise<WrappedKeyBytes>;
  unwrapKey(unwrappingKey: RsaOaepPrivateKey, wrappedKey: WrappedKeyBytes): Promise<AesGcmKey>;

  // PBKDF2
  deriveKeyFromPassword(password: PlaintextBytes, salt: PlaintextBytes, iterations: number): Promise<Pbkdf2DerivedKey>;

  // Hash
  digest(algorithm: 'SHA-256', data: Uint8Array): Promise<DigestBytes>;
}

export interface AccountKeyStore {
  /** Get the account keys document for the current user. */
  getAccountKeys(): Promise<AccountKeysDocument | null>;

  /** Atomically update the account keys document. */
  transactAccountKeys(
    updater: (current: AccountKeysDocument) => AccountKeysDocument | Promise<AccountKeysDocument>
  ): Promise<void>;

  /** Set the account keys document (for genesis). */
  setAccountKeys(doc: AccountKeysDocument): Promise<void>;

  /** Get a keystore entry. */
  getKeystoreEntry(ledgerId: string): Promise<KeystoreEntry | null>;

  /** Set a keystore entry. */
  setKeystoreEntry(ledgerId: string, entry: KeystoreEntry): Promise<void>;

  /** Set a keystore entry's archival status. */
  setKeystoreArchivedStatus(docId: string, isArchived: boolean): Promise<void>;

  /** Get a pending device request. */
  getPendingDevice(deviceId: string): Promise<PendingDevice | null>;

  /** Set a pending device request. */
  setPendingDevice(deviceId: string, data: PendingDevice): Promise<void>;

  /** Atomically update account keys + pending device status together. */
  transactApproveDevice(
    accountUpdater: (current: AccountKeysDocument) => AccountKeysDocument | Promise<AccountKeysDocument>,
    pendingDeviceId: string,
    pendingUpdate: Partial<PendingDevice>
  ): Promise<void>;

  /** Subscribe to pending devices for the current user. */
  subscribePendingDevices(
    onSnapshot: (devices: PendingDevice[]) => void
  ): () => void;

  /** Subscribe to a specific pending device request. */
  subscribePendingDevice(
    deviceId: string,
    onSnapshot: (device: PendingDevice | null) => void
  ): () => void;

  /** Subscribe to the account keys document. */
  subscribeAccountKeys(
    onSnapshot: (doc: AccountKeysDocument | null) => void
  ): () => void;

  /** Subscribe to all keystore entries for the current user. */
  subscribeKeystore(
    onSnapshot: (entries: KeystoreEntry[]) => void
  ): () => void;

  /** Delete a pending device request. */
  deletePendingDevice(deviceId: string): Promise<void>;

  /** Delete all remote zero-knowledge keys and entries for the current user. */
  resetRemoteStore(): Promise<void>;
}

export interface LedgerEventStore {
  /** Write an encrypted event to the ledger. */
  appendEvent(ledgerId: string, eventId: string, data: { encryptedData: string; iv: string }): Promise<void>;

  /** Subscribe to all events in creation order. */
  subscribe(
    ledgerId: string,
    onSnapshot: (events: Array<{ encryptedData: string; iv: string; id: string }>) => void
  ): () => void;  // returns unsubscribe

  /** Get the first event (genesis). */
  getGenesisEvent(ledgerId: string): Promise<{ encryptedData: string; iv: string } | null>;

  /** Create the ledger document. */
  createLedger(ledgerId: string): Promise<void>;
}

export interface LocalDeviceStore {
  // Device identity
  getDeviceId(): string;
  getDeviceName(): string;
  setDeviceName(name: string): void;

  // Device key persistence
  saveDeviceKeys(keys: { privateKey: string; publicKey: string }): Promise<void>;
  loadDeviceKeys(): Promise<{ privateKey: string; publicKey: string } | null>;

  // Master key persistence (PRF cache)
  saveMasterKey(uid: string, key: AesGcmKey): Promise<void>;
  loadMasterKey(uid: string): Promise<AesGcmKey | null>;

  // Identity persistence (per-ledger signing keys)
  saveIdentity(ledgerId: string, keys: { privateKey: string; publicKey: string }): Promise<void>;
  loadIdentity(ledgerId: string): Promise<{ privateKey: string; publicKey: string } | null>;

  // PRF credential cache
  getPrfCredentialId(uid: string): string | null;
  setPrfCredentialId(uid: string, credentialId: string): void;

  // Clear all local states
  clearAll(): Promise<void>;
}

export interface AuthProvider {
  getCurrentUser(): { uid: string; isAnonymous: boolean; email?: string; displayName?: string } | null;
}

export interface PrfProvider {
  createCredential(
    userId: string,
    userName: string,
    displayName: string
  ): Promise<{ credentialId: string; prfResult: Uint8Array }>;
  
  getAssertion(
    credentialIds: string[]
  ): Promise<{ usedCredentialId: string; prfResult: Uint8Array }>;
}
