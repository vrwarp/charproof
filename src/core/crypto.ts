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
  WrappedKeyBytes
} from "./interfaces";
import type { EncryptedData } from "./types";
import { canonicalStringify } from "./canonicalStringify";
import {
  uint8ToBase64,
  base64ToUint8,
  uint8ToBase64Url,
  base64UrlToUint8
} from "./base64";

export { canonicalStringify };
export {
  uint8ToBase64,
  base64ToUint8,
  uint8ToBase64Url,
  base64UrlToUint8
} from "./base64";

let _crypto: CryptoProvider | null = null;

export function setCryptoProvider(provider: CryptoProvider) {
  _crypto = provider;
}

export function getCrypto(): CryptoProvider {
  if (!_crypto) {
    throw new Error("CryptoProvider not initialized. Call setCryptoProvider() first.");
  }
  return _crypto;
}

export async function generateSymmetricKey(length: 128 | 256 = 256): Promise<AesGcmKey> {
  return getCrypto().generateSymmetricKey(length);
}

export async function importSymmetricKey(b64: string): Promise<AesGcmKey> {
  const bytes = base64UrlToUint8(b64) as RawKeyBytes;
  return getCrypto().importSymmetricKey(bytes);
}

export async function exportSymmetricKey(key: AesGcmKey): Promise<string> {
  const bytes = await getCrypto().exportSymmetricKey(key);
  return uint8ToBase64Url(bytes);
}

export async function encrypt(key: AesGcmKey | Pbkdf2DerivedKey, plaintext: string): Promise<{ ciphertext: string; iv: string }> {
  const plainBytes = new TextEncoder().encode(plaintext) as PlaintextBytes;
  const { ciphertext, iv } = await getCrypto().encrypt(key, plainBytes);
  return {
    ciphertext: uint8ToBase64(ciphertext),
    iv: uint8ToBase64(iv)
  };
}

export async function decrypt(key: AesGcmKey | Pbkdf2DerivedKey, ciphertext: string, iv: string): Promise<string> {
  const cipherBytes = base64ToUint8(ciphertext) as CiphertextBytes;
  const ivBytes = base64ToUint8(iv) as IvBytes;
  const plainBytes = await getCrypto().decrypt(key, cipherBytes, ivBytes);
  return new TextDecoder().decode(plainBytes);
}

// ECDSA Signing
export async function generateIdentityKeyPair(): Promise<{ publicKey: EcdsaPublicKey; privateKey: EcdsaPrivateKey }> {
  return getCrypto().generateSigningKeyPair();
}

export async function exportPrivateKey(key: EcdsaPrivateKey): Promise<string> {
  const bytes = await getCrypto().exportSigningPrivateKey(key);
  return uint8ToBase64(bytes);
}

export async function exportPublicKey(key: EcdsaPublicKey): Promise<string> {
  const bytes = await getCrypto().exportSigningPublicKey(key);
  return uint8ToBase64(bytes);
}

export async function importPrivateKey(b64: string): Promise<EcdsaPrivateKey> {
  const bytes = base64ToUint8(b64) as Pkcs8Bytes;
  return getCrypto().importSigningPrivateKey(bytes);
}

export async function importPublicKey(b64: string): Promise<EcdsaPublicKey> {
  const bytes = base64ToUint8(b64) as SpkiBytes;
  return getCrypto().importSigningPublicKey(bytes);
}

export async function signAction(privateKey: EcdsaPrivateKey, action: any): Promise<string> {
  const serialized = canonicalStringify(action);
  const plainBytes = new TextEncoder().encode(serialized) as PlaintextBytes;
  const signatureBytes = await getCrypto().sign(privateKey, plainBytes);
  return uint8ToBase64(signatureBytes);
}

export async function verifySignature(publicKey: EcdsaPublicKey | string, signature: string, action: any): Promise<boolean> {
  const pubKey = typeof publicKey === "string" ? await importPublicKey(publicKey) : publicKey;
  const serialized = canonicalStringify(action);
  const plainBytes = new TextEncoder().encode(serialized) as PlaintextBytes;
  const signatureBytes = base64ToUint8(signature) as SignatureBytes;
  return getCrypto().verify(pubKey, signatureBytes, plainBytes);
}

export async function generateIdentityKeyPairFromSeed(_seed: string): Promise<{ publicKey: EcdsaPublicKey; privateKey: EcdsaPrivateKey }> {
  // Fallback to random ECDSA keypair for seed implementation as before
  return generateIdentityKeyPair();
}

// RSA Device keys
export async function generateDeviceKeyPair(): Promise<{ publicKey: RsaOaepPublicKey; privateKey: RsaOaepPrivateKey }> {
  return getCrypto().generateDeviceKeyPair();
}

export async function exportDevicePublicKey(key: RsaOaepPublicKey): Promise<string> {
  const bytes = await getCrypto().exportDevicePublicKey(key);
  return uint8ToBase64(bytes);
}

export async function exportDevicePrivateKey(key: RsaOaepPrivateKey): Promise<string> {
  const bytes = await getCrypto().exportDevicePrivateKey(key);
  return uint8ToBase64(bytes);
}

export async function importDevicePublicKey(b64: string): Promise<RsaOaepPublicKey> {
  const bytes = base64ToUint8(b64) as SpkiBytes;
  return getCrypto().importDevicePublicKey(bytes);
}

export async function importDevicePrivateKey(b64: string): Promise<RsaOaepPrivateKey> {
  const bytes = base64ToUint8(b64) as Pkcs8Bytes;
  return getCrypto().importDevicePrivateKey(bytes);
}

export async function wrapAmk(publicKey: RsaOaepPublicKey, amkRaw: ArrayBuffer): Promise<string> {
  const amk = await getCrypto().importSymmetricKey(new Uint8Array(amkRaw) as RawKeyBytes);
  const wrappedBytes = await getCrypto().wrapKey(publicKey, amk);
  return uint8ToBase64(wrappedBytes);
}

export async function unwrapAmk(privateKey: RsaOaepPrivateKey, wrappedB64: string): Promise<ArrayBuffer> {
  const wrappedBytes = base64ToUint8(wrappedB64) as WrappedKeyBytes;
  const aesKey = await getCrypto().unwrapKey(privateKey, wrappedBytes);
  const rawBytes = await getCrypto().exportSymmetricKey(aesKey);
  return rawBytes.buffer as ArrayBuffer;
}

export async function encryptPayload(key: AesGcmKey | Pbkdf2DerivedKey, plaintext: string): Promise<EncryptedData> {
  const { ciphertext, iv } = await encrypt(key, plaintext);
  return { encryptedData: ciphertext, iv };
}

export async function decryptPayload(key: AesGcmKey | Pbkdf2DerivedKey, payload: EncryptedData): Promise<string> {
  return decrypt(key, payload.encryptedData, payload.iv);
}

export async function encryptHybrid(
  recipientPublicKeyB64: string,
  plaintext: string
): Promise<EncryptedData & { wrappedKey: string }> {
  const aesKey = await generateSymmetricKey(256);
  const encrypted = await encryptPayload(aesKey, plaintext);
  
  const rawAesKey = await getCrypto().exportSymmetricKey(aesKey);
  const recipientPubKey = await importDevicePublicKey(recipientPublicKeyB64);
  const wrappedKey = await wrapAmk(recipientPubKey, rawAesKey.buffer as ArrayBuffer);
  
  return { ...encrypted, wrappedKey };
}

export async function decryptHybrid(
  privateKey: RsaOaepPrivateKey,
  payload: EncryptedData,
  wrappedKeyB64: string
): Promise<string> {
  const rawAesKey = await unwrapAmk(privateKey, wrappedKeyB64);
  const aesKey = await getCrypto().importSymmetricKey(new Uint8Array(rawAesKey) as RawKeyBytes);
  return decryptPayload(aesKey, payload);
}

export async function deriveKeyFromPassword(password: string): Promise<Pbkdf2DerivedKey> {
  const passwordBytes = new TextEncoder().encode(password) as PlaintextBytes;
  const saltBytes = new TextEncoder().encode("letusmeet-admin-token-salt") as PlaintextBytes;
  return getCrypto().deriveKeyFromPassword(passwordBytes, saltBytes, 100000);
}

export async function generateVerificationCode(publicKeyB64: string): Promise<string> {
  const dataBytes = new TextEncoder().encode(publicKeyB64);
  const hashBytes = await getCrypto().digest("SHA-256", dataBytes);
  const hashArray = Array.from(hashBytes);
  
  const num = (hashArray[0] << 16) | (hashArray[1] << 8) | hashArray[2];
  return (num % 1000000).toString().padStart(6, '0');
}

/**
 * Generates a deterministic, pseudorandom document key for a given ledgerId,
 * bound to the user's Active Master Key (AMK).
 */
export async function blindLedgerId(amk: AesGcmKey, ledgerId: string): Promise<string> {
  const amkRaw = await getCrypto().exportSymmetricKey(amk);
  
  // Create a sub-key for blinding using SHA-256 over the AMK and a context salt
  const encoder = new TextEncoder();
  const contextBytes = encoder.encode("keystore-blinding");
  const derivationInput = new Uint8Array(amkRaw.length + contextBytes.length);
  derivationInput.set(amkRaw);
  derivationInput.set(contextBytes, amkRaw.length);
  
  const keystoreKeyHash = await getCrypto().digest("SHA-256", derivationInput);
  
  // Hash the ledgerId with the derived keystore key
  const ledgerIdBytes = encoder.encode(ledgerId);
  const blindingInput = new Uint8Array(keystoreKeyHash.length + ledgerIdBytes.length);
  blindingInput.set(new Uint8Array(keystoreKeyHash));
  blindingInput.set(ledgerIdBytes, keystoreKeyHash.length);
  
  const finalHash = await getCrypto().digest("SHA-256", blindingInput);
  
  // Return base64url representation to be used safely as a Firestore Document ID
  return uint8ToBase64Url(new Uint8Array(finalHash));
}
