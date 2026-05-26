import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import {
  uint8ToBase64,
  base64ToUint8,
  uint8ToBase64Url,
  base64UrlToUint8
} from "../base64";
import { canonicalStringify } from "../canonicalStringify";
import {
  prepareAppendEventEnvelope,
  decryptAndValidateEvent,
  processLedgerEventSnapshot,
  prepareGenesisCredentials,
  attemptRecoveryWithToken
} from "../sessionLogic";
import {
  setCryptoProvider,
  generateSymmetricKey,
  exportSymmetricKey,
  exportPublicKey,
  generateIdentityKeyPair
} from "../crypto";
import { DeterministicCryptoProvider } from "./DeterministicMocks";

describe("Zero-Knowledge Core Base64 Utilities API Coverage", () => {
  it("should maintain Base64 and Base64Url identity roundtrips under property-based inputs", () => {
    fc.assert(
      fc.property(fc.uint8Array(), (bytes) => {
        // Standard Base64
        const b64 = uint8ToBase64(bytes);
        const decoded = base64ToUint8(b64);
        expect(new Uint8Array(decoded)).toEqual(new Uint8Array(bytes));

        // Base64Url
        const b64url = uint8ToBase64Url(bytes);
        const decodedUrl = base64UrlToUint8(b64url);
        expect(new Uint8Array(decodedUrl)).toEqual(new Uint8Array(bytes));
      })
    );
  });
});

describe("Zero-Knowledge Core Canonical Stringify API Coverage", () => {
  it("should canonicalize object keys deterministically", () => {
    const obj1 = { b: 2, a: 1, c: [ { y: 2, x: 1 } ] };
    const obj2 = { a: 1, b: 2, c: [ { x: 1, y: 2 } ] };
    
    expect(canonicalStringify(obj1)).toBe(canonicalStringify(obj2));
  });

  it("should handle arbitrary JSON dictionaries successfully without throwing", () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          fc.string().map(s => s.replace(/[\\"]/g, "")),
          fc.oneof(
            fc.string().map(s => s.replace(/[\\"]/g, "")),
            fc.integer(),
            fc.boolean()
          )
        ),
        (jsonObj) => {
          const str = canonicalStringify(jsonObj);
          expect(() => JSON.parse(str)).not.toThrow();
        }
      )
    );
  });
});

describe("Zero-Knowledge Core Session Logic API Coverage", () => {
  it("should generate genesis credentials and recover them correctly using the recovery token", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer(), async (seed) => {
        const cryptoProvider = new DeterministicCryptoProvider(seed);
        setCryptoProvider(cryptoProvider);

        // 1. Prepare Genesis Credentials
        const genesis = await prepareGenesisCredentials();
        expect(genesis.ownershipToken).toBeDefined();
        expect(genesis.creds.symmetricKey).toBeDefined();
        expect(genesis.creds.signingPrivateKey).toBeDefined();
        expect(genesis.creds.signingPublicKey).toBeDefined();

        // 2. Prepare and encrypt a genesis event envelope containing ownerRecovery
        const genesisEvent = await prepareAppendEventEnvelope(
          genesis.signingPrivateKey,
          genesis.creds.signingPublicKey,
          { type: "GENESIS" },
          genesis.symmetricKey,
          genesis.ownerRecovery
        );

        // 3. Attempt recovery with ownership token
        const recovered = await attemptRecoveryWithToken(
          genesis.ownershipToken,
          genesis.creds.symmetricKey,
          genesisEvent
        );

        expect(recovered).not.toBeNull();
        expect(recovered!.symmetricKey).toBe(genesis.creds.symmetricKey);
        expect(recovered!.signingPrivateKey).toBe(genesis.creds.signingPrivateKey);
        expect(recovered!.signingPublicKey).toBe(genesis.creds.signingPublicKey);
      }),
      { numRuns: 50 }
    );
  });

  it("should successfully encrypt, sign, decrypt, and validate sequential events", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer(),
        fc.array(fc.record({ msg: fc.string().map(s => s.replace(/[\\"]/g, "")), val: fc.integer() })),
        async (seed, rawActions) => {
          const cryptoProvider = new DeterministicCryptoProvider(seed);
          setCryptoProvider(cryptoProvider);

          const keyPair = await generateIdentityKeyPair();
          const pubB64 = await exportPublicKey(keyPair.publicKey);
          const symKey = await generateSymmetricKey(256);

          const rawEvents: Array<{ encryptedData: string; iv: string; id: string }> = [];

          for (let i = 0; i < rawActions.length; i++) {
            const action = { ...rawActions[i], index: i };
            const envelope = await prepareAppendEventEnvelope(
              keyPair.privateKey,
              pubB64,
              action,
              symKey
            );
            rawEvents.push({ ...envelope, id: `evt-${i}` });
          }

          const processed = await processLedgerEventSnapshot(rawEvents, symKey);
          expect(processed.length).toBe(rawActions.length);

          for (let i = 0; i < rawActions.length; i++) {
            expect(processed[i].signerPublicKey).toBe(pubB64);
            expect(processed[i].action.msg).toBe(rawActions[i].msg);
            expect(processed[i].action.val).toBe(rawActions[i].val);
            expect(processed[i].action.index).toBe(i);
          }
        }
      ),
      { numRuns: 50 }
    );
  });

  it("should return null when failing to decrypt with an incorrect key", async () => {
    const cryptoProvider = new DeterministicCryptoProvider(12345);
    setCryptoProvider(cryptoProvider);

    const keyPair = await generateIdentityKeyPair();
    const pubB64 = await exportPublicKey(keyPair.publicKey);
    const correctKey = await generateSymmetricKey(256);
    const incorrectKey = await generateSymmetricKey(256);

    const envelope = await prepareAppendEventEnvelope(
      keyPair.privateKey,
      pubB64,
      { msg: "Secret Action" },
      correctKey
    );

    // Try decrypting with wrong key
    const decrypted = await decryptAndValidateEvent(envelope.encryptedData, envelope.iv, incorrectKey);
    expect(decrypted).toBeNull();
  });
});
