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

export class WebCryptoProvider implements CryptoProvider {
  getRandomBytes(length: number): Uint8Array {
    return window.crypto.getRandomValues(new Uint8Array(length));
  }

  randomUUID(): string {
    return window.crypto.randomUUID();
  }

  async generateSymmetricKey(length: 128 | 256 = 256): Promise<AesGcmKey> {
    const key = await window.crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length,
      },
      true,
      ["encrypt", "decrypt"]
    );
    return key as unknown as AesGcmKey;
  }

  async importSymmetricKey(raw: RawKeyBytes): Promise<AesGcmKey> {
    const key = await window.crypto.subtle.importKey(
      "raw",
      raw as any,
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"]
    );
    return key as unknown as AesGcmKey;
  }

  async exportSymmetricKey(key: AesGcmKey): Promise<RawKeyBytes> {
    const buffer = await window.crypto.subtle.exportKey("raw", key as unknown as CryptoKey);
    return new Uint8Array(buffer) as unknown as RawKeyBytes;
  }

  async encrypt(key: AesGcmKey | Pbkdf2DerivedKey, plaintext: PlaintextBytes): Promise<{ ciphertext: CiphertextBytes; iv: IvBytes }> {
    const iv = this.getRandomBytes(12);
    const ciphertextBuf = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv as any,
      },
      key as unknown as CryptoKey,
      plaintext as any
    );
    return {
      ciphertext: new Uint8Array(ciphertextBuf) as unknown as CiphertextBytes,
      iv: iv as unknown as IvBytes
    };
  }

  async decrypt(key: AesGcmKey | Pbkdf2DerivedKey, ciphertext: CiphertextBytes, iv: IvBytes): Promise<PlaintextBytes> {
    const plaintextBuf = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv as any,
      },
      key as unknown as CryptoKey,
      ciphertext as any
    );
    return new Uint8Array(plaintextBuf) as unknown as PlaintextBytes;
  }

  async generateSigningKeyPair(): Promise<{ publicKey: EcdsaPublicKey; privateKey: EcdsaPrivateKey }> {
    const pair = await window.crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );
    return {
      publicKey: pair.publicKey as unknown as EcdsaPublicKey,
      privateKey: pair.privateKey as unknown as EcdsaPrivateKey
    };
  }

  async exportSigningPublicKey(key: EcdsaPublicKey): Promise<SpkiBytes> {
    const buffer = await window.crypto.subtle.exportKey("spki", key as unknown as CryptoKey);
    return new Uint8Array(buffer) as unknown as SpkiBytes;
  }

  async exportSigningPrivateKey(key: EcdsaPrivateKey): Promise<Pkcs8Bytes> {
    const buffer = await window.crypto.subtle.exportKey("pkcs8", key as unknown as CryptoKey);
    return new Uint8Array(buffer) as unknown as Pkcs8Bytes;
  }

  async importSigningPublicKey(spki: SpkiBytes): Promise<EcdsaPublicKey> {
    const key = await window.crypto.subtle.importKey(
      "spki",
      spki as any,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
    return key as unknown as EcdsaPublicKey;
  }

  async importSigningPrivateKey(pkcs8: Pkcs8Bytes): Promise<EcdsaPrivateKey> {
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      pkcs8 as any,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"]
    );
    return key as unknown as EcdsaPrivateKey;
  }

  async sign(privateKey: EcdsaPrivateKey, data: PlaintextBytes): Promise<SignatureBytes> {
    const signature = await window.crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      privateKey as unknown as CryptoKey,
      data as any
    );
    return new Uint8Array(signature) as unknown as SignatureBytes;
  }

  async verify(publicKey: EcdsaPublicKey, signature: SignatureBytes, data: PlaintextBytes): Promise<boolean> {
    return window.crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      publicKey as unknown as CryptoKey,
      signature as any,
      data as any
    );
  }

  async generateDeviceKeyPair(): Promise<{ publicKey: RsaOaepPublicKey; privateKey: RsaOaepPrivateKey }> {
    const pair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      } as any,
      true,
      ["wrapKey", "unwrapKey"]
    );
    return {
      publicKey: pair.publicKey as unknown as RsaOaepPublicKey,
      privateKey: pair.privateKey as unknown as RsaOaepPrivateKey
    };
  }

  async exportDevicePublicKey(key: RsaOaepPublicKey): Promise<SpkiBytes> {
    const buffer = await window.crypto.subtle.exportKey("spki", key as unknown as CryptoKey);
    return new Uint8Array(buffer) as unknown as SpkiBytes;
  }

  async exportDevicePrivateKey(key: RsaOaepPrivateKey): Promise<Pkcs8Bytes> {
    const buffer = await window.crypto.subtle.exportKey("pkcs8", key as unknown as CryptoKey);
    return new Uint8Array(buffer) as unknown as Pkcs8Bytes;
  }

  async importDevicePublicKey(spki: SpkiBytes): Promise<RsaOaepPublicKey> {
    const key = await window.crypto.subtle.importKey(
      "spki",
      spki as any,
      { name: "RSA-OAEP", hash: "SHA-256" } as any,
      true,
      ["wrapKey"]
    );
    return key as unknown as RsaOaepPublicKey;
  }

  async importDevicePrivateKey(pkcs8: Pkcs8Bytes): Promise<RsaOaepPrivateKey> {
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      pkcs8 as any,
      { name: "RSA-OAEP", hash: "SHA-256" } as any,
      true,
      ["unwrapKey"]
    );
    return key as unknown as RsaOaepPrivateKey;
  }

  async wrapKey(wrappingKey: RsaOaepPublicKey, keyToWrap: AesGcmKey): Promise<WrappedKeyBytes> {
    const wrapped = await window.crypto.subtle.wrapKey(
      "raw",
      keyToWrap as unknown as CryptoKey,
      wrappingKey as unknown as CryptoKey,
      "RSA-OAEP"
    );
    return new Uint8Array(wrapped) as unknown as WrappedKeyBytes;
  }

  async unwrapKey(unwrappingKey: RsaOaepPrivateKey, wrappedKey: WrappedKeyBytes): Promise<AesGcmKey> {
    const unwrapped = await window.crypto.subtle.unwrapKey(
      "raw",
      wrappedKey as any,
      unwrappingKey as unknown as CryptoKey,
      { name: "RSA-OAEP", hash: "SHA-256" } as any,
      { name: "AES-GCM" } as any,
      true,
      ["encrypt", "decrypt"]
    );
    return unwrapped as unknown as AesGcmKey;
  }

  async deriveKeyFromPassword(password: PlaintextBytes, salt: PlaintextBytes, iterations: number): Promise<Pbkdf2DerivedKey> {
    const baseKey = await window.crypto.subtle.importKey(
      "raw",
      password as any,
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    const derived = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt as any,
        iterations,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    return derived as unknown as Pbkdf2DerivedKey;
  }

  async digest(algorithm: 'SHA-256', data: Uint8Array): Promise<DigestBytes> {
    const buffer = await window.crypto.subtle.digest(algorithm, data as any);
    return new Uint8Array(buffer) as unknown as DigestBytes;
  }
}
