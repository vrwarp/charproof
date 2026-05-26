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
  WrappedKeyBytes
} from "../core/interfaces";

// Simple mock implementation of DOM CryptoKey to keep the typechecker happy
class MockCryptoKey implements CryptoKey {
  readonly algorithm: KeyAlgorithm;
  readonly extractable: boolean;
  readonly type: KeyType;
  readonly usages: KeyUsage[];
  readonly rawKeyMaterial: Uint8Array;

  constructor(type: KeyType, rawKeyMaterial: Uint8Array, algorithmName: string) {
    this.type = type;
    this.rawKeyMaterial = rawKeyMaterial;
    this.extractable = true;
    this.usages = [];
    this.algorithm = { name: algorithmName };
  }
}

export class MockCryptoProvider implements CryptoProvider {
  getRandomBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
  }

  randomUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  // AES-GCM
  async generateSymmetricKey(length: 128 | 256 = 256): Promise<AesGcmKey> {
    const bytes = this.getRandomBytes(length / 8);
    return new MockCryptoKey("secret", bytes, "AES-GCM") as any;
  }

  async importSymmetricKey(raw: RawKeyBytes): Promise<AesGcmKey> {
    return new MockCryptoKey("secret", new Uint8Array(raw), "AES-GCM") as any;
  }

  async exportSymmetricKey(key: AesGcmKey): Promise<RawKeyBytes> {
    const mockKey = key as any as MockCryptoKey;
    return new Uint8Array(mockKey.rawKeyMaterial) as RawKeyBytes;
  }

  // Transparent AES-GCM Encryption / Decryption
  async encrypt(key: AesGcmKey | Pbkdf2DerivedKey, plaintext: PlaintextBytes): Promise<{ ciphertext: CiphertextBytes; iv: IvBytes }> {
    const mockKey = key as any as MockCryptoKey;
    // Prefix payload with the key material so that decrypt() can verify it's the correct key (matching production behaviour)
    const keyMaterial = mockKey.rawKeyMaterial;
    const header = new Uint8Array([109, 111, 99, 107, 45, 107, 101, 121, 58, ...keyMaterial, 58]); // "mock-key:[material]:"
    const ciphertext = new Uint8Array(header.length + plaintext.length);
    ciphertext.set(header, 0);
    ciphertext.set(plaintext, header.length);

    const iv = new Uint8Array(12);
    iv.set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    return {
      ciphertext: ciphertext as CiphertextBytes,
      iv: iv as IvBytes
    };
  }

  async decrypt(key: AesGcmKey | Pbkdf2DerivedKey, ciphertext: CiphertextBytes, _iv: IvBytes): Promise<PlaintextBytes> {
    const mockKey = key as any as MockCryptoKey;
    const keyMaterial = mockKey.rawKeyMaterial;
    const header = new Uint8Array([109, 111, 99, 107, 45, 107, 101, 121, 58, ...keyMaterial, 58]);

    // Validate key match
    if (ciphertext.length < header.length) {
      throw new Error("Decryption failed (ciphertext too short)");
    }
    for (let i = 0; i < header.length; i++) {
      if (ciphertext[i] !== header[i]) {
        throw new Error("Decryption failed: key mismatch or ciphertext corrupted");
      }
    }

    return ciphertext.slice(header.length) as PlaintextBytes;
  }

  // ECDSA
  async generateSigningKeyPair(): Promise<{ publicKey: EcdsaPublicKey; privateKey: EcdsaPrivateKey }> {
    const pubBytes = this.getRandomBytes(16);
    return {
      publicKey: new MockCryptoKey("public", pubBytes, "ECDSA") as any,
      privateKey: new MockCryptoKey("private", pubBytes, "ECDSA") as any
    };
  }

  async exportSigningPublicKey(key: EcdsaPublicKey): Promise<SpkiBytes> {
    const mockKey = key as any as MockCryptoKey;
    return new Uint8Array(mockKey.rawKeyMaterial) as SpkiBytes;
  }

  async exportSigningPrivateKey(key: EcdsaPrivateKey): Promise<Pkcs8Bytes> {
    const mockKey = key as any as MockCryptoKey;
    return new Uint8Array(mockKey.rawKeyMaterial) as Pkcs8Bytes;
  }

  async importSigningPublicKey(spki: SpkiBytes): Promise<EcdsaPublicKey> {
    return new MockCryptoKey("public", new Uint8Array(spki), "ECDSA") as any;
  }

  async importSigningPrivateKey(pkcs8: Pkcs8Bytes): Promise<EcdsaPrivateKey> {
    return new MockCryptoKey("private", new Uint8Array(pkcs8), "ECDSA") as any;
  }

  async sign(privateKey: EcdsaPrivateKey, data: PlaintextBytes): Promise<SignatureBytes> {
    const mockKey = privateKey as any as MockCryptoKey;
    const keyMaterial = mockKey.rawKeyMaterial;
    const signature = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      signature[i] = data[i] ^ keyMaterial[i % keyMaterial.length];
    }
    return signature as any as SignatureBytes;
  }

  async verify(publicKey: EcdsaPublicKey, signature: SignatureBytes, data: PlaintextBytes): Promise<boolean> {
    const mockKey = publicKey as any as MockCryptoKey;
    const keyMaterial = mockKey.rawKeyMaterial;

    if (signature.length !== data.length) {
      return false;
    }

    for (let i = 0; i < data.length; i++) {
      const expected = data[i] ^ keyMaterial[i % keyMaterial.length];
      if (signature[i] !== expected) {
        return false;
      }
    }
    return true;
  }

  // RSA-OAEP
  async generateDeviceKeyPair(): Promise<{ publicKey: RsaOaepPublicKey; privateKey: RsaOaepPrivateKey }> {
    const pubBytes = this.getRandomBytes(16);
    return {
      publicKey: new MockCryptoKey("public", pubBytes, "RSA-OAEP") as any,
      privateKey: new MockCryptoKey("private", pubBytes, "RSA-OAEP") as any
    };
  }

  async exportDevicePublicKey(key: RsaOaepPublicKey): Promise<SpkiBytes> {
    const mockKey = key as any as MockCryptoKey;
    return new Uint8Array(mockKey.rawKeyMaterial) as SpkiBytes;
  }

  async exportDevicePrivateKey(key: RsaOaepPrivateKey): Promise<Pkcs8Bytes> {
    const mockKey = key as any as MockCryptoKey;
    return new Uint8Array(mockKey.rawKeyMaterial) as Pkcs8Bytes;
  }

  async importDevicePublicKey(spki: SpkiBytes): Promise<RsaOaepPublicKey> {
    return new MockCryptoKey("public", new Uint8Array(spki), "RSA-OAEP") as any;
  }

  async importDevicePrivateKey(pkcs8: Pkcs8Bytes): Promise<RsaOaepPrivateKey> {
    return new MockCryptoKey("private", new Uint8Array(pkcs8), "RSA-OAEP") as any;
  }

  // Transparent Key Wrapping
  async wrapKey(_wrappingKey: RsaOaepPublicKey, keyToWrap: AesGcmKey): Promise<WrappedKeyBytes> {
    const mockKey = keyToWrap as any as MockCryptoKey;
    return new Uint8Array(mockKey.rawKeyMaterial) as WrappedKeyBytes;
  }

  async unwrapKey(_unwrappingKey: RsaOaepPrivateKey, wrappedKey: WrappedKeyBytes): Promise<AesGcmKey> {
    return new MockCryptoKey("secret", new Uint8Array(wrappedKey), "AES-GCM") as any;
  }

  // PBKDF2
  async deriveKeyFromPassword(password: PlaintextBytes, _salt: PlaintextBytes, _iterations: number): Promise<Pbkdf2DerivedKey> {
    // Transparently wrap the password as the PBKDF2 derived key material
    return new MockCryptoKey("secret", new Uint8Array(password), "PBKDF2") as any;
  }

  // SHA-256
  async digest(_algorithm: 'SHA-256', data: Uint8Array): Promise<DigestBytes> {
    const hash = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      hash[i] = (data[i % data.length] || 0) ^ i;
    }
    return hash as DigestBytes;
  }
}
