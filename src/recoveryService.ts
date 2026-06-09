import * as bip39 from 'bip39';
import {
  exportDevicePublicKey,
  encrypt,
  decrypt,
  wrapAmk,
  unwrapAmk,
  encryptPayload,
  getCrypto,
  generateDeviceKeyPair,
  exportDevicePrivateKey,
  importDevicePrivateKey,
  PBKDF2_ITERATIONS
} from './core/crypto';
import { uint8ToBase64Url, base64UrlToUint8 } from './core/base64';
import { getActiveAmk } from './deviceService';
import type { AccountKeysDocument } from './core/types';
import type { AesGcmKey, RsaOaepPublicKey, RsaOaepPrivateKey, AccountKeyStore, AuthProvider, RawKeyBytes, PlaintextBytes } from './core/interfaces';
import { FirestoreAccountKeyStore } from "./browser/FirestoreAccountKeyStore";
import { FirebaseAuthProvider } from "./browser/FirebaseAuthProvider";

let store: AccountKeyStore = new FirestoreAccountKeyStore();
let auth: AuthProvider = new FirebaseAuthProvider();

export function setRecoveryProviders(providers: {
  accountKeyStore?: AccountKeyStore;
  authProvider?: AuthProvider;
}) {
  if (providers.accountKeyStore) store = providers.accountKeyStore;
  if (providers.authProvider) auth = providers.authProvider;
}

/**
 * # Cryptographic Specification: Asymmetric Recovery Phrase (Symmetric-Wrapped RSA)
 * 
 * To implement asymmetric recovery while ensuring compatibility with the browser's native `Web Crypto API`, we will use a hybrid model where the recovery phrase protects a persistent RSA-OAEP key pair.
 * 
 * ## 1. Key Generation (Setup)
 * 1.  **Mnemonic:** Generate a 24-word BIP39 mnemonic.
 * 2.  **RSA Pair:** Generate a random **RSA-OAEP 2048-bit Key Pair** (The AIRK).
 * 3.  **Symmetric Protector:** Derive a symmetric **AES-GCM 256-bit Key** from the mnemonic using PBKDF2 (100,000 iterations, SHA-256).
 * 4.  **Seal Private Key:** Encrypt the RSA Private Key (exported as PKCS8) with the Symmetric Protector.
 * 5.  **Registration:** Store in `recoveryMethods`:
 *     *   `publicKey`: The RSA Public Key (Base64 SPKI).
 *     *   `encryptedPrivateKey`: The encrypted RSA Private Key + IV (Base64).
 * 
 * ## 2. AMK Wrapping (Rotation)
 * Active devices perform rotations using only the public data:
 * 1.  Fetch `publicKey` from the `recoveryMethods` entry.
 * 2.  Wrap the **new AMK** using RSA-OAEP and the `publicKey`.
 * 3.  Store in `keyring` under the recovery method's ID.
 * 
 * ## 3. Recovery Flow
 * 1.  User enters phrase.
 * 2.  Derive the **Symmetric Protector** (PBKDF2).
 * 3.  Fetch `encryptedPrivateKey` from Firestore.
 * 4.  Decrypt the **RSA Private Key**.
 * 5.  Unwrap the latest **AMK** from the `keyring`.
 */
export async function setupPhraseRecovery(): Promise<string> {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) throw new Error("Must be signed in.");

  // 1. Generate mnemonic
  const mnemonic = bip39.generateMnemonic(256);
  
  // 2. Generate random RSA-OAEP key pair for recovery using getCrypto()
  const rsaPair = await getCrypto().generateDeviceKeyPair();

  // 3. Derive symmetric key from phrase using a fresh random salt
  const kdfSalt = uint8ToBase64Url(getCrypto().getRandomBytes(16));
  const kdfIterations = PBKDF2_ITERATIONS;
  const protector = await deriveProtectorFromPhrase(mnemonic, kdfSalt, kdfIterations);

  // 4. Encrypt Private Key with protector
  const privKeyRaw = await getCrypto().exportDevicePrivateKey(rsaPair.privateKey);
  const privKeyB64 = btoa(String.fromCharCode(...new Uint8Array(privKeyRaw)));
  const { ciphertext: encryptedPrivKey, iv } = await encrypt(protector, privKeyB64);
  
  // 5. Wrap AMK with the new RSA Public Key
  const { amk, amkId } = await getActiveAmk();
  const rawAmk = await getCrypto().exportSymmetricKey(amk);
  const wrappedAmk = await wrapAmk(rsaPair.publicKey, rawAmk.buffer as ArrayBuffer);
  
  const pubKeyB64 = await exportDevicePublicKey(rsaPair.publicKey);

  // 6. Save to Firestore via AccountKeyStore transaction
  await store.transactAccountKeys(async (data) => {
    const encryptedRecLabel = await encryptPayload(amk, "Primary Recovery Phrase");
    data.recoveryMethods["__recovery_phrase"] = {
      type: 'phrase',
      encryptedLabel: encryptedRecLabel,
      publicKey: pubKeyB64,
      createdAt: Date.now()
    };
    // Add custom field to recoveryMethods for the encrypted private key,
    // including the per-record PBKDF2 salt + iterations needed to re-derive
    // the protector during recovery.
    (data.recoveryMethods["__recovery_phrase"] as any).encryptedPrivateKey = JSON.stringify({
      ciphertext: encryptedPrivKey,
      iv,
      kdfSalt,
      kdfIterations
    });
    
    data.keyring[amkId]["__recovery_phrase"] = wrappedAmk;
    return data;
  });

  return mnemonic;
}

/**
 * Recovers the AMK using a recovery phrase.
 */
export async function recoverAmkWithPhrase(mnemonic: string): Promise<{ amk: AesGcmKey, amkId: string }> {
  const user = auth.getCurrentUser();
  if (!user || user.isAnonymous) throw new Error("Must be signed in.");

  const data = await store.getAccountKeys();
  if (!data) throw new Error("Account keys not found.");
  
  const method = data.recoveryMethods["__recovery_phrase"];
  if (!method || !method.publicKey) throw new Error("Recovery phrase method not set up.");
  
  const encryptedPrivData = (method as any).encryptedPrivateKey;
  if (!encryptedPrivData) throw new Error("Recovery private key missing from Firestore.");
  
  const { ciphertext, iv, kdfSalt, kdfIterations } = JSON.parse(encryptedPrivData);

  // 1. Derive protector. Legacy entries (pre-random-salt) carry no kdfSalt; fall
  // back to the original constant salt + iteration count for backward compatibility.
  const protector = kdfSalt
    ? await deriveProtectorFromPhrase(mnemonic, kdfSalt, kdfIterations)
    : await deriveProtectorFromPhraseLegacy(mnemonic);

  // 2. Decrypt RSA Private Key
  const privKeyB64 = await decrypt(protector, ciphertext, iv);
  const privKeyRaw = Uint8Array.from(atob(privKeyB64), c => c.charCodeAt(0));
  
  const privateKey = await getCrypto().importDevicePrivateKey(privKeyRaw as any);

  // 3. Unwrap AMK
  const amkId = data.activeAmkId;
  const wrappedAmk = data.keyring[amkId]["__recovery_phrase"];
  if (!wrappedAmk) throw new Error("Recovery wrapper missing from keyring.");
  
  const amkBuffer = await unwrapAmk(privateKey, wrappedAmk);
  const amk = await getCrypto().importSymmetricKey(new Uint8Array(amkBuffer) as RawKeyBytes);

  return { amk, amkId };
}

async function deriveProtectorFromPhrase(
  mnemonic: string,
  saltB64: string,
  iterations: number
): Promise<AesGcmKey> {
  const seed = await bip39.mnemonicToSeed(mnemonic);
  const password = new Uint8Array(seed.slice(0, 32)) as PlaintextBytes;
  const salt = base64UrlToUint8(saltB64) as unknown as PlaintextBytes;
  return (await getCrypto().deriveKeyFromPassword(password, salt, iterations)) as unknown as AesGcmKey;
}

/** Backward-compatible derivation for phrase recovery entries created before
 *  per-record random salts were introduced (constant salt, 100k iterations). */
async function deriveProtectorFromPhraseLegacy(mnemonic: string): Promise<AesGcmKey> {
  const seed = await bip39.mnemonicToSeed(mnemonic);
  const password = new Uint8Array(seed.slice(0, 32)) as PlaintextBytes;
  const salt = new TextEncoder().encode("LetUsMeet-Recovery-Salt-v1") as PlaintextBytes;
  return (await getCrypto().deriveKeyFromPassword(password, salt, 100000)) as unknown as AesGcmKey;
}
