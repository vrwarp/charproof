// Entry point for `@letusmeet/zero-knowledge`

// Dependency Injection Config
export { initializeZK, getDb, getAuth } from "./config";

// Types
export * from "./types";

// Low-level crypto
export {
  generateSymmetricKey,
  importSymmetricKey,
  exportSymmetricKey,
  encrypt,
  decrypt,
  generateIdentityKeyPair,
  exportPrivateKey,
  exportPublicKey,
  importPrivateKey,
  importPublicKey,
  signAction,
  verifySignature,
  generateIdentityKeyPairFromSeed,
  canonicalStringify,
  generateDeviceKeyPair,
  exportDevicePublicKey,
  exportDevicePrivateKey,
  importDevicePublicKey,
  importDevicePrivateKey,
  wrapAmk,
  unwrapAmk,
  encryptPayload,
  decryptPayload,
  encryptHybrid,
  decryptHybrid,
  deriveKeyFromPassword,
  generateVerificationCode,
  setCryptoProvider
} from "./crypto";

// IndexedDB key store
export {
  openDB,
  DB_NAME,
  DB_VERSION,
  STORE_IDENTITIES,
  STORE_MASTER_KEYS,
  STORE_DEVICE_KEYS
} from "./idb";

// WebAuthn PRF
export {
  clearPrfSessionCache,
  derivePrfMasterKey,
  loadMasterKeyFromIndexedDB,
  setPrfProviders
} from "./prfService";

// Device Management, AMK and Keystore
export {
  getDeviceId,
  getDeviceName,
  setDeviceName,
  loadDeviceKeysFromIndexedDB,
  getLocalPublicKey,
  clearAmkSessionCache,
  getActiveAmk,
  getAmkById,
  getRecoveryStatus,
  registerCurrentDevice,
  enablePrfRecovery,
  revokeDevice,
  saveToKeystore,
  loadFromKeystore,
  hasAccountKeys,
  verifyAmk,
  requestDeviceAuthorization,
  approveDeviceAuthorization,
  getVerificationCodeForPublicKey,
  getLocalVerificationCode,
  setDeviceServiceProviders,
  subscribePendingRequests,
  subscribeAuthorizedDevices,
  subscribeCurrentDeviceStatus,
  subscribeToUserKeystore,
  rejectDeviceRequest,
  resetLocalStorage,
  resetUserAccountRemote,
  archiveKeystoreEntry,
  unarchiveKeystoreEntry,
  type DecryptedDevice
} from "./deviceService";

// Phrase recovery (AIRK)
export {
  setupPhraseRecovery,
  recoverAmkWithPhrase,
  setRecoveryProviders
} from "./recoveryService";

// Session
export {
  DefaultLedgerSession,
  createLedgerSession,
  getLedgerSession,
  setSessionProviders,
  setLedgerDecoyPool
} from "./session";

// Ledger event store (export so apps can inject a decoy-configured instance)
export {
  FirestoreLedgerEventStore,
  type LedgerEventStoreOptions
} from "./browser/FirestoreLedgerEventStore";
