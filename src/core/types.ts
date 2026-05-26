/**
 * @file types.ts
 * @description Core types and schema definitions for the Charproof zero-knowledge library.
 * These types represent both the ciphertext data stored in Firestore and the decrypted structures
 * resolved locally on authorized devices.
 */

/**
 * Represents encrypted payload metadata as stored in the untrusted database.
 * Uses AES-GCM 256-bit symmetric encryption.
 */
export interface EncryptedData {
  /**
   * Base64-encoded AES-GCM ciphertext.
   */
  encryptedData: string;

  /**
   * Base64-encoded AES-GCM initialization vector (IV).
   */
  iv: string;
}

/**
 * Represents a document entry in the user's remote Firestore keystore.
 * The keystore preserves symmetric ledger keys wrapped by the active Account Master Key.
 */
export interface KeystoreEntry extends EncryptedData {
  /**
   * The unique ID of the Account Master Key (AMK) version used to encrypt this entry.
   */
  amkId: string;

  /**
   * Millisecond timestamp indicating when this keystore entry was last updated.
   */
  updatedAt: number;

  /**
   * Optional flag indicating if this entry has been archived (e.g. hidden from active dashboard).
   */
  isArchived?: boolean;
}

/**
 * A decrypted keystore entry resolved securely on the client.
 */
export interface DecryptedKeystoreEntry extends KeystoreEntry {
  /**
   * The recovered plaintext ID of the ledger.
   */
  ledgerId?: string;
}

/**
 * Represents public identity metadata of an authorized device.
 */
export interface DevicePublicKey {
  /**
   * Unique identifier of the device (typically generated locally).
   */
  deviceId: string;

  /**
   * Encrypted device display name, preventing the database from viewing human-readable names.
   */
  encryptedDeviceName: EncryptedData;

  /**
   * Base64-encoded SubjectPublicKeyInfo (SPKI) RSA-OAEP public key.
   * Used by other devices to wrap the Account Master Key during rotation.
   */
  publicKey: string;

  /**
   * Millisecond timestamp of when this device was enrolled.
   */
  createdAt: number;
}

/**
 * Configured key recovery methods for the user's root account.
 */
export interface RecoveryMethod {
  /**
   * Recovery mechanism type:
   * - `'prf'`: Hardware passkey recovery via WebAuthn PRF extension.
   * - `'phrase'`: Mnemonic 24-word BIP39 backup phrase recovery.
   */
  type: 'prf' | 'phrase';

  /**
   * Encrypted descriptive label for this recovery method (e.g. "Primary Backup").
   */
  encryptedLabel: EncryptedData;

  /**
   * Optional: Base64 RSA-OAEP public key used in phrase-based asymmetric recovery.
   */
  publicKey?: string;

  /**
   * Optional: WebAuthn credential ID used for hardware PRF recovery.
   */
  credentialId?: string;

  /**
   * Millisecond timestamp when the recovery method was configured.
   */
  createdAt: number;
}

/**
 * The master zero-knowledge account document stored in Firestore `/users/{uid}`.
 * Maps active devices, recovery methods, and the encrypted Account Master Key matrix.
 */
export interface AccountKeysDocument {
  /**
   * The version ID of the currently active Account Master Key (AMK) (e.g., "amk_v1").
   */
  activeAmkId: string;

  /**
   * Record mapping registered device IDs to their corresponding public keys.
   */
  devices: Record<string, DevicePublicKey>;

  /**
   * Record mapping recovery method IDs to their corresponding recovery structures.
   */
  recoveryMethods: Record<string, RecoveryMethod>;

  /**
   * A double-nested keyring matrix mapping AMK Version ID -> Device/Recovery ID -> Base64 Wrapped AMK.
   * Enables decentralized key sharing: a device decrypts its segment using its local private key
   * to recover the active AMK.
   */
  keyring: Record<string, Record<string, string>>;
}

/**
 * Represents an enrollment request from a new device pending approval.
 */
export interface PendingDevice {
  /**
   * Unique identifier of the requesting device.
   */
  deviceId: string;

  /**
   * Encrypted device details containing the wrapped ephemeral key segment.
   */
  encryptedDeviceName: EncryptedData & {
    /**
     * Map of sponsorDeviceId -> Base64 Wrapped Ephemeral Symmetric Key.
     * Allows authorized primary devices to decrypt the name securely.
     */
    wrappedKeys: Record<string, string>;
  };

  /**
   * Base64 SPKI RSA-OAEP public key of the requesting device.
   */
  publicKey: string;

  /**
   * Authorization request status.
   */
  status: 'pending' | 'authorized' | 'rejected';

  /**
   * Millisecond timestamp when the request was initiated.
   */
  createdAt: number;

  /**
   * Optional millisecond timestamp when this request will expire.
   */
  expiresAt?: number;
}

/**
 * Decrypted client-side ledger credentials required to sign and encrypt events.
 */
export interface LedgerCredentials {
  /**
   * Base64-encoded AES-GCM 256-bit symmetric session key used for event payload encryption.
   */
  symmetricKey: string;

  /**
   * Base64-encoded PKCS#8 ECDSA private key used to sign new events locally.
   */
  signingPrivateKey: string;

  /**
   * Base64-encoded SPKI ECDSA public key used to verify signatures on ledger events.
   */
  signingPublicKey: string;
}

/**
 * A client-side decrypted and signature-verified event retrieved from the ledger.
 */
export interface DecryptedLedgerEvent {
  /**
   * Base64 SPKI ECDSA public key of the device that authored this event.
   */
  signerPublicKey: string;

  /**
   * The original plaintext action payload decrypted client-side.
   */
  action: any;
}

/**
 * Represents a live, active client-side decrypted event log session.
 */
export interface LedgerSession {
  /**
   * Encrypts and appends a new action payload to the remote ledger.
   * @param action The plaintext payload to append.
   */
  appendEvent(action: any): Promise<void>;

  /**
   * Subscribes to real-time decrypted updates of the ledger events.
   * @param onUpdate Callback triggered with all decrypted, verified events.
   * @returns Unsubscribe function to stop listening.
   */
  subscribe(onUpdate: (events: DecryptedLedgerEvent[]) => void): () => void;

  /**
   * Retrieves the very first event in the ledger (Genesis).
   */
  getGenesisEvent(): Promise<DecryptedLedgerEvent | null>;

  /**
   * Exports the raw decrypted symmetric session key of the ledger.
   */
  exportSessionKey(): string;

  /**
   * Exports the public signing key of the local device.
   */
  getSignerPublicKey(): string;
}

/**
 * The result returned when a new zero-knowledge ledger session is successfully created.
 */
export interface CreateLedgerResult {
  /**
   * The live, active ledger session instance.
   */
  session: LedgerSession;

  /**
   * An ownership token allowing anonymous or other devices to recover the ledger.
   */
  ownershipToken: string;

  /**
   * The unique ID of the newly created ledger.
   */
  ledgerId: string;
}
