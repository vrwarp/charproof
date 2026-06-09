import type {
  CryptoProvider,
  AesGcmKey,
  EcdsaPublicKey,
  EcdsaPrivateKey,
  RsaOaepPublicKey,
  RsaOaepPrivateKey,
  Pbkdf2DerivedKey,
  RawKeyBytes,
  SpkiBytes,
  Pkcs8Bytes,
  CiphertextBytes,
  IvBytes,
  PlaintextBytes,
  SignatureBytes,
  DigestBytes,
  WrappedKeyBytes,
  AccountKeyStore,
  LedgerEventStore,
  LocalDeviceStore,
  AuthProvider,
  PrfProvider
} from "../interfaces";
import type { AccountKeysDocument, KeystoreEntry, PendingDevice } from "../types";

// Seedable PRNG (Mulberry32)
export function createPRNG(seed: number) {
  let state = seed >>> 0;
  return function next() {
    state = (state + 0x6D2B79F5) | 0;
    let t = Math.imul(state ^ (state >>> 15), state | 1);
    t = (t + Math.imul(t ^ (t >>> 7), t | 61)) | 0;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Concrete Mock implementation of standard CryptoKey
export class MockCryptoKey implements CryptoKey {
  readonly type: KeyType;
  readonly extractable: boolean;
  readonly algorithm: KeyAlgorithm;
  readonly usages: KeyUsage[];
  readonly keyMaterial: Uint8Array;
  readonly id: string;

  constructor(
    type: KeyType,
    algorithmName: string,
    usages: KeyUsage[],
    keyMaterial: Uint8Array,
    id: string
  ) {
    this.type = type;
    this.extractable = true;
    this.algorithm = { name: algorithmName } as KeyAlgorithm;
    this.usages = usages;
    this.keyMaterial = keyMaterial;
    this.id = id;
  }
}

// Deterministic Cryptographic Provider
export class DeterministicCryptoProvider implements CryptoProvider {
  private prng: () => number;
  private keyIdCounter = 0;

  constructor(seed: number) {
    this.prng = createPRNG(seed);
  }

  getRandomBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(this.prng() * 256) & 0xff;
    }
    return bytes;
  }

  randomUUID(): string {
    const bytes = this.getRandomBytes(16);
    // Format as v4 UUID: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex: string[] = [];
    for (let i = 0; i < 16; i++) {
      hex.push(bytes[i].toString(16).padStart(2, "0"));
    }
    return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
  }

  async generateSymmetricKey(length: 128 | 256 = 256): Promise<AesGcmKey> {
    const bytes = this.getRandomBytes(length / 8);
    const id = `sym-key-${++this.keyIdCounter}`;
    return new MockCryptoKey("secret", "AES-GCM", ["encrypt", "decrypt"], bytes, id) as unknown as AesGcmKey;
  }

  async importSymmetricKey(raw: RawKeyBytes): Promise<AesGcmKey> {
    const id = `sym-key-imported-${++this.keyIdCounter}`;
    return new MockCryptoKey("secret", "AES-GCM", ["encrypt", "decrypt"], new Uint8Array(raw), id) as unknown as AesGcmKey;
  }

  async exportSymmetricKey(key: AesGcmKey): Promise<RawKeyBytes> {
    const mockKey = key as unknown as MockCryptoKey;
    return new Uint8Array(mockKey.keyMaterial) as unknown as RawKeyBytes;
  }

  private xorCipher(keyBytes: Uint8Array, ivBytes: Uint8Array, data: Uint8Array): Uint8Array {
    // Generate a deterministic keystream from the combination of key and IV
    let seed = 12345;
    for (let i = 0; i < keyBytes.length; i++) seed = (seed + keyBytes[i] * (i + 1)) | 0;
    for (let i = 0; i < ivBytes.length; i++) seed = (seed + ivBytes[i] * (i + 13)) | 0;
    
    const cipherPrng = createPRNG(seed);
    const result = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      result[i] = data[i] ^ (Math.floor(cipherPrng() * 256) & 0xff);
    }
    return result;
  }

  async encrypt(key: AesGcmKey | Pbkdf2DerivedKey, plaintext: PlaintextBytes): Promise<{ ciphertext: CiphertextBytes; iv: IvBytes }> {
    const mockKey = key as unknown as MockCryptoKey;
    const iv = this.getRandomBytes(12) as unknown as IvBytes;
    const cipherBytes = this.xorCipher(mockKey.keyMaterial, iv as unknown as Uint8Array, new Uint8Array(plaintext));
    return {
      ciphertext: cipherBytes as unknown as CiphertextBytes,
      iv
    };
  }

  async decrypt(key: AesGcmKey | Pbkdf2DerivedKey, ciphertext: CiphertextBytes, iv: IvBytes): Promise<PlaintextBytes> {
    const mockKey = key as unknown as MockCryptoKey;
    const plainBytes = this.xorCipher(mockKey.keyMaterial, iv as unknown as Uint8Array, new Uint8Array(ciphertext));
    return plainBytes as unknown as PlaintextBytes;
  }

  async generateSigningKeyPair(): Promise<{ publicKey: EcdsaPublicKey; privateKey: EcdsaPrivateKey }> {
    const pairId = `ecdsa-pair-${++this.keyIdCounter}`;
    const privBytes = new TextEncoder().encode(`ecdsa-priv-for-${pairId}`);
    const pubBytes = new TextEncoder().encode(`ecdsa-pub-for-${pairId}`);
    
    return {
      publicKey: new MockCryptoKey("public", "ECDSA", ["verify"], pubBytes, pairId) as unknown as EcdsaPublicKey,
      privateKey: new MockCryptoKey("private", "ECDSA", ["sign"], privBytes, pairId) as unknown as EcdsaPrivateKey
    };
  }

  async exportSigningPublicKey(key: EcdsaPublicKey): Promise<SpkiBytes> {
    const mockKey = key as unknown as MockCryptoKey;
    return new Uint8Array(mockKey.keyMaterial) as unknown as SpkiBytes;
  }

  async exportSigningPrivateKey(key: EcdsaPrivateKey): Promise<Pkcs8Bytes> {
    const mockKey = key as unknown as MockCryptoKey;
    return new Uint8Array(mockKey.keyMaterial) as unknown as Pkcs8Bytes;
  }

  async importSigningPublicKey(spki: SpkiBytes): Promise<EcdsaPublicKey> {
    const text = new TextDecoder().decode(spki);
    let pairId = "imported";
    if (text.startsWith("ecdsa-pub-for-")) {
      pairId = text.substring("ecdsa-pub-for-".length);
    }
    return new MockCryptoKey("public", "ECDSA", ["verify"], new Uint8Array(spki), pairId) as unknown as EcdsaPublicKey;
  }

  async importSigningPrivateKey(pkcs8: Pkcs8Bytes): Promise<EcdsaPrivateKey> {
    const text = new TextDecoder().decode(pkcs8);
    let pairId = "imported";
    if (text.startsWith("ecdsa-priv-for-")) {
      pairId = text.substring("ecdsa-priv-for-".length);
    }
    return new MockCryptoKey("private", "ECDSA", ["sign"], new Uint8Array(pkcs8), pairId) as unknown as EcdsaPrivateKey;
  }

  async sign(privateKey: EcdsaPrivateKey, data: PlaintextBytes): Promise<SignatureBytes> {
    const mockKey = privateKey as unknown as MockCryptoKey;
    let seed = 54321;
    for (let i = 0; i < mockKey.id.length; i++) seed = (seed + mockKey.id.charCodeAt(i) * (i + 1)) | 0;
    for (let i = 0; i < data.length; i++) seed = (seed + data[i] * (i + 7)) | 0;
    
    const sigPrng = createPRNG(seed);
    const signature = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      signature[i] = Math.floor(sigPrng() * 256) & 0xff;
    }
    return signature as unknown as SignatureBytes;
  }

  async verify(publicKey: EcdsaPublicKey, signature: SignatureBytes, data: PlaintextBytes): Promise<boolean> {
    const mockKey = publicKey as unknown as MockCryptoKey;
    let seed = 54321;
    for (let i = 0; i < mockKey.id.length; i++) seed = (seed + mockKey.id.charCodeAt(i) * (i + 1)) | 0;
    for (let i = 0; i < data.length; i++) seed = (seed + data[i] * (i + 7)) | 0;
    
    const sigPrng = createPRNG(seed);
    const expected = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      expected[i] = Math.floor(sigPrng() * 256) & 0xff;
    }
    
    const sigBytes = new Uint8Array(signature);
    if (sigBytes.length !== 64) return false;
    for (let i = 0; i < 64; i++) {
      if (sigBytes[i] !== expected[i]) return false;
    }
    return true;
  }

  async generateDeviceKeyPair(): Promise<{ publicKey: RsaOaepPublicKey; privateKey: RsaOaepPrivateKey }> {
    const pairId = `rsa-pair-${++this.keyIdCounter}`;
    const privBytes = new TextEncoder().encode(`rsa-priv-for-${pairId}`);
    const pubBytes = new TextEncoder().encode(`rsa-pub-for-${pairId}`);
    
    return {
      publicKey: new MockCryptoKey("public", "RSA-OAEP", ["wrapKey"], pubBytes, pairId) as unknown as RsaOaepPublicKey,
      privateKey: new MockCryptoKey("private", "RSA-OAEP", ["unwrapKey"], privBytes, pairId) as unknown as RsaOaepPrivateKey
    };
  }

  async exportDevicePublicKey(key: RsaOaepPublicKey): Promise<SpkiBytes> {
    const mockKey = key as unknown as MockCryptoKey;
    return new Uint8Array(mockKey.keyMaterial) as unknown as SpkiBytes;
  }

  async exportDevicePrivateKey(key: RsaOaepPrivateKey): Promise<Pkcs8Bytes> {
    const mockKey = key as unknown as MockCryptoKey;
    return new Uint8Array(mockKey.keyMaterial) as unknown as Pkcs8Bytes;
  }

  async importDevicePublicKey(spki: SpkiBytes): Promise<RsaOaepPublicKey> {
    const text = new TextDecoder().decode(spki);
    let pairId = "imported";
    if (text.startsWith("rsa-pub-for-")) {
      pairId = text.substring("rsa-pub-for-".length);
    }
    return new MockCryptoKey("public", "RSA-OAEP", ["wrapKey"], new Uint8Array(spki), pairId) as unknown as RsaOaepPublicKey;
  }

  async importDevicePrivateKey(pkcs8: Pkcs8Bytes): Promise<RsaOaepPrivateKey> {
    const text = new TextDecoder().decode(pkcs8);
    let pairId = "imported";
    if (text.startsWith("rsa-priv-for-")) {
      pairId = text.substring("rsa-priv-for-".length);
    }
    return new MockCryptoKey("private", "RSA-OAEP", ["unwrapKey"], new Uint8Array(pkcs8), pairId) as unknown as RsaOaepPrivateKey;
  }

  async wrapKey(wrappingKey: RsaOaepPublicKey, keyToWrap: AesGcmKey): Promise<WrappedKeyBytes> {
    const pubKey = wrappingKey as unknown as MockCryptoKey;
    const targetKey = keyToWrap as unknown as MockCryptoKey;
    let seed = 99999;
    for (let i = 0; i < pubKey.id.length; i++) seed = (seed + pubKey.id.charCodeAt(i) * (i + 1)) | 0;
    
    const wrapPrng = createPRNG(seed);
    const wrapped = new Uint8Array(targetKey.keyMaterial.length);
    for (let i = 0; i < targetKey.keyMaterial.length; i++) {
      wrapped[i] = targetKey.keyMaterial[i] ^ (Math.floor(wrapPrng() * 256) & 0xff);
    }
    
    const metaBytes = new TextEncoder().encode(`ID:${targetKey.id}:`);
    const result = new Uint8Array(metaBytes.length + wrapped.length);
    result.set(metaBytes, 0);
    result.set(wrapped, metaBytes.length);
    return result as unknown as WrappedKeyBytes;
  }

  async unwrapKey(unwrappingKey: RsaOaepPrivateKey, wrappedKey: WrappedKeyBytes): Promise<AesGcmKey> {
    const privKey = unwrappingKey as unknown as MockCryptoKey;
    const wrapped = new Uint8Array(wrappedKey);
    
    const text = new TextDecoder().decode(wrapped);
    if (!text.startsWith("ID:")) {
      throw new Error("Invalid wrapped key format: missing metadata prefix.");
    }
    const endOfMeta = text.indexOf(":", 3);
    if (endOfMeta === -1) {
      throw new Error("Invalid wrapped key format: missing metadata end.");
    }
    const originalKeyId = text.substring(3, endOfMeta);
    
    const metaBytesLength = endOfMeta + 1;
    const wrappedKeyBytes = wrapped.subarray(metaBytesLength);
    
    let seed = 99999;
    for (let i = 0; i < privKey.id.length; i++) seed = (seed + privKey.id.charCodeAt(i) * (i + 1)) | 0;
    
    const wrapPrng = createPRNG(seed);
    const unwrapped = new Uint8Array(wrappedKeyBytes.length);
    for (let i = 0; i < wrappedKeyBytes.length; i++) {
      unwrapped[i] = wrappedKeyBytes[i] ^ (Math.floor(wrapPrng() * 256) & 0xff);
    }
    
    return new MockCryptoKey("secret", "AES-GCM", ["encrypt", "decrypt"], unwrapped, originalKeyId) as unknown as AesGcmKey;
  }

  async deriveKeyFromPassword(password: PlaintextBytes, salt: PlaintextBytes, iterations: number): Promise<Pbkdf2DerivedKey> {
    let seed = iterations;
    const passArr = new Uint8Array(password);
    const saltArr = new Uint8Array(salt);
    for (let i = 0; i < passArr.length; i++) seed = (seed + passArr[i] * (i + 1)) | 0;
    for (let i = 0; i < saltArr.length; i++) seed = (seed + saltArr[i] * (i + 13)) | 0;
    
    const derivePrng = createPRNG(seed);
    const keyMaterial = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      keyMaterial[i] = Math.floor(derivePrng() * 256) & 0xff;
    }
    return new MockCryptoKey("secret", "AES-GCM", ["encrypt", "decrypt"], keyMaterial, "pbkdf2-key") as unknown as Pbkdf2DerivedKey;
  }

  async digest(_algorithm: "SHA-256", data: Uint8Array): Promise<DigestBytes> {
    let seed = 987654321;
    for (let i = 0; i < data.length; i++) {
      seed = (seed + data[i] * (i + 1)) | 0;
    }
    const digestPrng = createPRNG(seed);
    const digest = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      digest[i] = Math.floor(digestPrng() * 256) & 0xff;
    }
    return digest as unknown as DigestBytes;
  }
}

// In-Memory, Deterministic Account Key Store (Firestore Mock)
export class MockAccountKeyStore implements AccountKeyStore {
  public accountKeys: AccountKeysDocument | null = null;
  public keystore: Record<string, KeystoreEntry> = {};
  public pendingDevices: Record<string, PendingDevice> = {};
  
  public transactionAttempts = 0;
  public transactionCollisionsToSimulate = 0;
  public onTransactionAttempt?: () => void | Promise<void>;

  async getAccountKeys(): Promise<AccountKeysDocument | null> {
    return this.accountKeys ? JSON.parse(JSON.stringify(this.accountKeys)) : null;
  }

  async transactAccountKeys(
    updater: (current: AccountKeysDocument) => AccountKeysDocument | Promise<AccountKeysDocument>
  ): Promise<void> {
    if (!this.accountKeys) {
      throw new Error("Cannot transact: account keys document does not exist.");
    }

    let success = false;
    while (!success) {
      this.transactionAttempts++;
      if (this.onTransactionAttempt) {
        await this.onTransactionAttempt();
      }

      const clone = JSON.parse(JSON.stringify(this.accountKeys)) as AccountKeysDocument;
      const updated = await updater(clone);

      if (this.transactionCollisionsToSimulate > 0) {
        this.transactionCollisionsToSimulate--;
        const currentKeys = this.accountKeys;
        if (currentKeys) {
          const concurrentClone = JSON.parse(JSON.stringify(currentKeys));
          concurrentClone.activeAmkId = `amk_collided_${Date.now()}_${Math.random()}`;
          this.accountKeys = concurrentClone;
        }
        continue;
      }

      this.accountKeys = updated;
      success = true;
    }
  }

  async setAccountKeys(doc: AccountKeysDocument): Promise<void> {
    this.accountKeys = JSON.parse(JSON.stringify(doc));
  }

  async createAccountKeys(doc: AccountKeysDocument): Promise<boolean> {
    if (this.accountKeys) {
      return false;
    }
    this.accountKeys = JSON.parse(JSON.stringify(doc));
    return true;
  }

  async getKeystoreEntry(ledgerId: string): Promise<KeystoreEntry | null> {
    const entry = this.keystore[ledgerId];
    return entry ? JSON.parse(JSON.stringify(entry)) : null;
  }

  async setKeystoreEntry(ledgerId: string, entry: KeystoreEntry): Promise<void> {
    this.keystore[ledgerId] = JSON.parse(JSON.stringify(entry));
  }

  async setKeystoreArchivedStatus(docId: string, isArchived: boolean): Promise<void> {
    if (this.keystore[docId]) {
      this.keystore[docId].isArchived = isArchived;
    }
  }

  async getPendingDevice(deviceId: string): Promise<PendingDevice | null> {
    const pending = this.pendingDevices[deviceId];
    return pending ? JSON.parse(JSON.stringify(pending)) : null;
  }

  async setPendingDevice(deviceId: string, data: PendingDevice): Promise<void> {
    this.pendingDevices[deviceId] = JSON.parse(JSON.stringify(data));
  }

  async transactApproveDevice(
    accountUpdater: (current: AccountKeysDocument) => AccountKeysDocument | Promise<AccountKeysDocument>,
    pendingDeviceId: string,
    pendingUpdate: Partial<PendingDevice>
  ): Promise<void> {
    await this.transactAccountKeys(accountUpdater);
    
    if (this.pendingDevices[pendingDeviceId]) {
      this.pendingDevices[pendingDeviceId] = {
        ...this.pendingDevices[pendingDeviceId],
        ...pendingUpdate
      };
    }
  }

  subscribePendingDevices(onSnapshot: (devices: PendingDevice[]) => void): () => void {
    onSnapshot(Object.values(this.pendingDevices).filter(d => d.status === "pending"));
    return () => {};
  }

  subscribePendingDevice(deviceId: string, onSnapshot: (device: PendingDevice | null) => void): () => void {
    onSnapshot(this.pendingDevices[deviceId] || null);
    return () => {};
  }

  subscribeAccountKeys(onSnapshot: (doc: AccountKeysDocument | null) => void): () => void {
    onSnapshot(this.accountKeys);
    return () => {};
  }

  subscribeKeystore(onSnapshot: (entries: KeystoreEntry[]) => void): () => void {
    onSnapshot(Object.values(this.keystore));
    return () => {};
  }

  async deletePendingDevice(deviceId: string): Promise<void> {
    delete this.pendingDevices[deviceId];
  }

  async resetRemoteStore(): Promise<void> {
    this.accountKeys = null;
    this.keystore = {};
    this.pendingDevices = {};
  }
}

// In-Memory, Deterministic Event Store (Firestore Mock)
export class MockLedgerEventStore implements LedgerEventStore {
  public ledgers: Record<string, boolean> = {};
  public events: Record<string, Array<{ encryptedData: string; iv: string; id: string }>> = {};
  private listeners: Record<string, Array<(evs: Array<{ encryptedData: string; iv: string; id: string }>) => void>> = {};

  async appendEvent(ledgerId: string, eventId: string, data: { encryptedData: string; iv: string }): Promise<void> {
    if (!this.events[ledgerId]) {
      this.events[ledgerId] = [];
    }
    const event = { ...data, id: eventId };
    this.events[ledgerId].push(event);

    if (this.listeners[ledgerId]) {
      const snapshot = JSON.parse(JSON.stringify(this.events[ledgerId]));
      for (const listener of this.listeners[ledgerId]) {
        listener(snapshot);
      }
    }
  }

  subscribe(
    ledgerId: string,
    onSnapshot: (events: Array<{ encryptedData: string; iv: string; id: string }>) => void
  ): () => void {
    if (!this.listeners[ledgerId]) {
      this.listeners[ledgerId] = [];
    }
    this.listeners[ledgerId].push(onSnapshot);
    
    const snapshot = this.events[ledgerId] ? JSON.parse(JSON.stringify(this.events[ledgerId])) : [];
    onSnapshot(snapshot);

    return () => {
      this.listeners[ledgerId] = this.listeners[ledgerId].filter(l => l !== onSnapshot);
    };
  }

  async getGenesisEvent(ledgerId: string): Promise<{ encryptedData: string; iv: string } | null> {
    const list = this.events[ledgerId];
    if (!list || list.length === 0) return null;
    return { encryptedData: list[0].encryptedData, iv: list[0].iv };
  }

  async createLedger(ledgerId: string): Promise<void> {
    this.ledgers[ledgerId] = true;
    this.events[ledgerId] = [];
  }
}

// In-Memory Local Device Store (LocalStorage / IndexedDB Mock)
export class MockLocalDeviceStore implements LocalDeviceStore {
  public deviceId: string;
  public deviceName: string;
  public deviceKeys: { privateKey: string; publicKey: string } | null = null;
  public masterKeys: Record<string, AesGcmKey> = {};
  public identities: Record<string, { privateKey: string; publicKey: string }> = {};
  public prfCredentials: Record<string, string> = {};

  constructor(deviceId: string, deviceName: string) {
    this.deviceId = deviceId;
    this.deviceName = deviceName;
  }

  getDeviceId(): string {
    return this.deviceId;
  }

  getDeviceName(): string {
    return this.deviceName;
  }

  setDeviceName(name: string): void {
    this.deviceName = name;
  }

  async saveDeviceKeys(keys: { privateKey: string; publicKey: string }): Promise<void> {
    this.deviceKeys = { ...keys };
  }

  async loadDeviceKeys(): Promise<{ privateKey: string; publicKey: string } | null> {
    return this.deviceKeys ? { ...this.deviceKeys } : null;
  }

  async saveMasterKey(uid: string, key: AesGcmKey): Promise<void> {
    this.masterKeys[uid] = key;
  }

  async loadMasterKey(uid: string): Promise<AesGcmKey | null> {
    return this.masterKeys[uid] || null;
  }

  async saveIdentity(ledgerId: string, keys: { privateKey: string; publicKey: string }): Promise<void> {
    this.identities[ledgerId] = { ...keys };
  }

  async loadIdentity(ledgerId: string): Promise<{ privateKey: string; publicKey: string } | null> {
    return this.identities[ledgerId] ? { ...this.identities[ledgerId] } : null;
  }

  getPrfCredentialId(uid: string): string | null {
    return this.prfCredentials[uid] || null;
  }

  setPrfCredentialId(uid: string, credentialId: string): void {
    this.prfCredentials[uid] = credentialId;
  }

  async clearAll(): Promise<void> {
    this.deviceKeys = null;
    this.masterKeys = {};
    this.identities = {};
    this.prfCredentials = {};
  }
}

// Concrete Mock Auth Provider
export class MockAuthProvider implements AuthProvider {
  public currentUser: { uid: string; isAnonymous: boolean; email?: string; displayName?: string } | null = null;

  getCurrentUser(): { uid: string; isAnonymous: boolean; email?: string; displayName?: string } | null {
    return this.currentUser ? { ...this.currentUser } : null;
  }
}

// Concrete Mock PRF Provider
export class MockPrfProvider implements PrfProvider {
  private prfSeedCounter = 0;

  async createCredential(
    userId: string,
    userName: string,
    displayName: string
  ): Promise<{ credentialId: string; prfResult: Uint8Array }> {
    const credId = `mock-prf-cred-${++this.prfSeedCounter}`;
    let seed = 12345;
    for (let i = 0; i < credId.length; i++) seed = (seed + credId.charCodeAt(i) * (i + 1)) | 0;
    const prng = createPRNG(seed);
    const prfResult = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      prfResult[i] = Math.floor(prng() * 256) & 0xff;
    }
    return { credentialId: credId, prfResult };
  }

  async getAssertion(
    credentialIds: string[]
  ): Promise<{ usedCredentialId: string; prfResult: Uint8Array }> {
    if (credentialIds.length === 0) {
      throw new Error("No credential IDs provided for assertion.");
    }
    const credId = credentialIds[0];
    let seed = 12345;
    for (let i = 0; i < credId.length; i++) seed = (seed + credId.charCodeAt(i) * (i + 1)) | 0;
    const prng = createPRNG(seed);
    const prfResult = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      prfResult[i] = Math.floor(prng() * 256) & 0xff;
    }
    return { usedCredentialId: credId, prfResult };
  }
}
