import type {
  AesGcmKey,
  EcdsaPrivateKey,
  EcdsaPublicKey,
  PlaintextBytes,
  CiphertextBytes,
  IvBytes
} from "./interfaces";
import type {
  EncryptedData,
  DecryptedLedgerEvent,
  LedgerCredentials
} from "./types";
import {
  generateSymmetricKey,
  generateIdentityKeyPair,
  exportSymmetricKey,
  exportPrivateKey,
  exportPublicKey,
  deriveKeyFromPassword,
  encryptPayload,
  decryptPayload,
  signAction,
  verifySignature,
  getCrypto
} from "./crypto";

export async function prepareAppendEventEnvelope(
  signingPrivateKey: EcdsaPrivateKey,
  signingPublicKeyB64: string,
  action: any,
  symmetricKey: AesGcmKey,
  ownerRecovery: EncryptedData | null = null
): Promise<EncryptedData> {
  const signature = await signAction(signingPrivateKey, action);
  const envelope: any = {
    publicKey: signingPublicKeyB64,
    signature,
    action
  };
  if (ownerRecovery) {
    envelope.__ownerRecovery = ownerRecovery;
  }
  const json = JSON.stringify(envelope);
  return encryptPayload(symmetricKey, json);
}

export async function decryptAndValidateEvent(
  encryptedData: string,
  iv: string,
  symmetricKey: AesGcmKey
): Promise<DecryptedLedgerEvent | null> {
  try {
    const json = await decryptPayload(symmetricKey, { encryptedData, iv });
    const envelope = JSON.parse(json);
    const isValid = await verifySignature(envelope.publicKey, envelope.signature, envelope.action);
    if (isValid) {
      return { signerPublicKey: envelope.publicKey, action: envelope.action };
    }
  } catch (e) {
    console.warn("Failed to decrypt or validate event", e);
  }
  return null;
}

export async function processLedgerEventSnapshot(
  rawEvents: Array<{ encryptedData: string; iv: string; id: string }>,
  symmetricKey: AesGcmKey
): Promise<DecryptedLedgerEvent[]> {
  const decryptedPromises = rawEvents.map(raw =>
    decryptAndValidateEvent(raw.encryptedData, raw.iv, symmetricKey)
  );
  const decryptedResults = await Promise.all(decryptedPromises);

  const events: DecryptedLedgerEvent[] = [];
  for (const decrypted of decryptedResults) {
    if (decrypted) {
      events.push(decrypted);
    }
  }
  return events;
}

export interface GenesisMaterial {
  creds: LedgerCredentials;
  ownershipToken: string;
  ownerRecovery: EncryptedData;
  symmetricKey: AesGcmKey;
  signingPrivateKey: EcdsaPrivateKey;
  signingPublicKey: EcdsaPublicKey;
}

export async function prepareGenesisCredentials(): Promise<GenesisMaterial> {
  const symmetricKey = await generateSymmetricKey(256);
  const keyPair = await generateIdentityKeyPair();
  
  const b64Key = await exportSymmetricKey(symmetricKey);
  const privB64 = await exportPrivateKey(keyPair.privateKey);
  const pubB64 = await exportPublicKey(keyPair.publicKey);

  // Generate ownership recovery token
  const ownershipToken = getCrypto().randomUUID();
  const tokenKey = await deriveKeyFromPassword(ownershipToken);
  const ownerRecovery = await encryptPayload(tokenKey, privB64);

  const creds: LedgerCredentials = {
    symmetricKey: b64Key,
    signingPrivateKey: privB64,
    signingPublicKey: pubB64
  };

  return {
    creds,
    ownershipToken,
    ownerRecovery,
    symmetricKey,
    signingPrivateKey: keyPair.privateKey,
    signingPublicKey: keyPair.publicKey
  };
}

export async function attemptRecoveryWithToken(
  ownershipToken: string,
  shareableKeyB64: string,
  genesisEventEncrypted: { encryptedData: string; iv: string }
): Promise<LedgerCredentials | null> {
  try {
    const symKey = await getCrypto().importSymmetricKey(
      base64UrlToUint8(shareableKeyB64) as any
    );
    const json = await decryptPayload(symKey, genesisEventEncrypted);
    const envelope = JSON.parse(json);
    
    if (envelope.__ownerRecovery) {
      const tokenKey = await deriveKeyFromPassword(ownershipToken);
      const privB64 = await decryptPayload(tokenKey, envelope.__ownerRecovery);
      const pubB64 = envelope.publicKey;
      
      return {
        symmetricKey: shareableKeyB64,
        signingPrivateKey: privB64,
        signingPublicKey: pubB64
      };
    }
  } catch (e) {
    console.error("Owner recovery token decryption failed:", e);
  }
  return null;
}

function base64UrlToUint8(b64url: string): Uint8Array {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) {
    b64 += "=";
  }
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
