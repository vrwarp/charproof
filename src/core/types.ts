// === FIRESTORE SCHEMA (server-visible ciphertext) ===

export interface EncryptedData {
  encryptedData: string; // AES-GCM ciphertext (Base64)
  iv: string;            // AES-GCM IV (Base64)
}

export interface KeystoreEntry extends EncryptedData {
  amkId: string;    // Explicitly declare which AMK encrypted this payload
  updatedAt: number;
  isArchived?: boolean;
}

export interface DecryptedKeystoreEntry extends KeystoreEntry {
  ledgerId?: string; // Restored securely on the client-side after decryption
}

export interface DevicePublicKey {
  deviceId: string;
  encryptedDeviceName: EncryptedData;
  publicKey: string; // Base64 SPKI (RSA-OAEP)
  createdAt: number;
}

export interface RecoveryMethod {
  type: 'prf' | 'phrase';
  encryptedLabel: EncryptedData;
  publicKey?: string; // Optional: For asymmetric recovery (e.g., RSA Public Key for phrases)
  credentialId?: string; // Optional: For PRF recovery (WebAuthn credential ID)
  createdAt: number;
}

export interface AccountKeysDocument {
  activeAmkId: string; // e.g., "amk_v1"
  devices: Record<string, DevicePublicKey>; // Keyed by deviceId
  recoveryMethods: Record<string, RecoveryMethod>; // Keyed by methodId (e.g., "__recovery_prf")
  keyring: Record<string, Record<string, string>>;
  // Map of amkId -> { (deviceId | recoveryMethodId): "wrapped_amk_base64" }
}

export interface PendingDevice {
  deviceId: string;
  encryptedDeviceName: EncryptedData & {
    wrappedKeys: Record<string, string>; // Maps sponsorDeviceId -> wrappedEphemeralKeyB64
  };
  publicKey: string; // Base64 SPKI
  status: 'pending' | 'authorized' | 'rejected';
  createdAt: number;
  expiresAt?: number;
}

export interface LedgerCredentials {
  symmetricKey: string;
  signingPrivateKey: string;
  signingPublicKey: string;
}

export interface DecryptedLedgerEvent {
  signerPublicKey: string;
  action: any;
}

export interface LedgerSession {
  appendEvent(action: any): Promise<void>;
  subscribe(onUpdate: (events: DecryptedLedgerEvent[]) => void): () => void;
  getGenesisEvent(): Promise<DecryptedLedgerEvent | null>;
  exportSessionKey(): string;
  getSignerPublicKey(): string;
}

export interface CreateLedgerResult {
  session: LedgerSession;
  ownershipToken: string;
  ledgerId: string;
}
