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
  symmetricKey: AesGcmKey,
  authorizedSigners?: Set<string> | null
): Promise<DecryptedLedgerEvent | null> {
  try {
    const json = await decryptPayload(symmetricKey, { encryptedData, iv });
    const envelope = JSON.parse(json);

    // Authorship authentication: when an allowlist is supplied, the embedded
    // signer key must be a known-authorized participant. Without this, anyone
    // holding the shared symmetric key could mint a keypair and impersonate
    // another author, since the signature only certifies its own embedded key.
    if (authorizedSigners && !authorizedSigners.has(envelope.publicKey)) {
      console.warn("Rejecting event signed by an unauthorized public key.");
      return null;
    }

    const isValid = await verifySignature(envelope.publicKey, envelope.signature, envelope.action);
    if (isValid) {
      return { signerPublicKey: envelope.publicKey, action: envelope.action };
    }
  } catch (e) {
    console.warn("Failed to decrypt or validate event", e);
  }
  return null;
}

export interface ProcessSnapshotOptions {
  /** Allowlist of authorized signer public keys; see decryptAndValidateEvent. */
  authorizedSigners?: Set<string> | null;
  /** Optional memoization cache keyed by `${id}:${iv}` to skip re-decrypting
   *  events that were already processed in a previous snapshot. */
  cache?: Map<string, DecryptedLedgerEvent | null>;
}

export async function processLedgerEventSnapshot(
  rawEvents: Array<{ encryptedData: string; iv: string; id: string }>,
  symmetricKey: AesGcmKey,
  options: ProcessSnapshotOptions = {}
): Promise<DecryptedLedgerEvent[]> {
  const { authorizedSigners = null, cache } = options;

  const decryptedResults = await Promise.all(
    rawEvents.map(async raw => {
      const cacheKey = `${raw.id}:${raw.iv}`;
      if (cache && cache.has(cacheKey)) {
        return cache.get(cacheKey) ?? null;
      }
      const result = await decryptAndValidateEvent(
        raw.encryptedData,
        raw.iv,
        symmetricKey,
        authorizedSigners
      );
      if (cache) cache.set(cacheKey, result);
      return result;
    })
  );

  const events: DecryptedLedgerEvent[] = [];
  for (const decrypted of decryptedResults) {
    if (decrypted) {
      events.push(decrypted);
    }
  }
  return events;
}

/** Encrypted owner-recovery payload plus the PBKDF2 parameters needed to
 *  re-derive the token key during recovery. */
export type OwnerRecoveryEnvelope = EncryptedData & { kdfSalt: string; kdfIterations: number };

export interface GenesisMaterial {
  creds: LedgerCredentials;
  ownershipToken: string;
  ownerRecovery: OwnerRecoveryEnvelope;
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

  // Generate ownership recovery token. The PBKDF2 salt + iteration count are
  // stored inside the recovery envelope so the key can be re-derived; the salt
  // is random per-ledger rather than a shared constant.
  const ownershipToken = getCrypto().randomUUID();
  const { key: tokenKey, salt: kdfSalt, iterations: kdfIterations } = await deriveKeyFromPassword(ownershipToken);
  const encryptedOwner = await encryptPayload(tokenKey, privB64);
  const ownerRecovery = { ...encryptedOwner, kdfSalt, kdfIterations };

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
      const rec = envelope.__ownerRecovery;
      const { key: tokenKey } = await deriveKeyFromPassword(ownershipToken, {
        salt: rec.kdfSalt,
        iterations: rec.kdfIterations
      });
      const privB64 = await decryptPayload(tokenKey, rec);
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
