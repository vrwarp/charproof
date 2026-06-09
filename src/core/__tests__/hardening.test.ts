import { describe, it, expect, beforeEach } from "vitest";
import {
  prepareGenesisDocument,
  prepareRegistrationData,
  rotateKeys,
  unwrapAmkById,
  parseEncryptedEnvelopeB64
} from "../deviceLogic";
import {
  prepareAppendEventEnvelope,
  decryptAndValidateEvent,
  processLedgerEventSnapshot
} from "../sessionLogic";
import {
  setCryptoProvider,
  generateSymmetricKey,
  generateIdentityKeyPair,
  exportPublicKey,
  generateDeviceKeyPair,
  exportDevicePublicKey,
  exportDevicePrivateKey,
  wrapAmk,
  canonicalStringify
} from "../crypto";
import { DeterministicCryptoProvider } from "./DeterministicMocks";

describe("Hardening regression coverage", () => {
  let crypto: DeterministicCryptoProvider;

  beforeEach(() => {
    crypto = new DeterministicCryptoProvider(2024);
    setCryptoProvider(crypto);
  });

  // ──────────────────────────────────────────────────────────────────
  // Authorship authentication (authorized-signer allowlist)
  // ──────────────────────────────────────────────────────────────────
  describe("authorized-signer allowlist", () => {
    it("rejects a validly-signed event whose signer is not in the allowlist", async () => {
      const symKey = await generateSymmetricKey(256);

      const authorized = await generateIdentityKeyPair();
      const authorizedPub = await exportPublicKey(authorized.publicKey);

      const impostor = await generateIdentityKeyPair();
      const impostorPub = await exportPublicKey(impostor.publicKey);

      // The impostor self-certifies: signs with its own key and embeds its own pubkey.
      const env = await prepareAppendEventEnvelope(impostor.privateKey, impostorPub, { type: "FORGED" }, symKey);

      // Without an allowlist, the self-signed event is accepted (legacy/trust-all).
      const permissive = await decryptAndValidateEvent(env.encryptedData, env.iv, symKey);
      expect(permissive).not.toBeNull();
      expect(permissive!.signerPublicKey).toBe(impostorPub);

      // With an allowlist that excludes the impostor, it is rejected.
      const allow = new Set([authorizedPub]);
      const rejected = await decryptAndValidateEvent(env.encryptedData, env.iv, symKey, allow);
      expect(rejected).toBeNull();
    });

    it("processLedgerEventSnapshot filters unauthorized signers", async () => {
      const symKey = await generateSymmetricKey(256);
      const good = await generateIdentityKeyPair();
      const goodPub = await exportPublicKey(good.publicKey);
      const bad = await generateIdentityKeyPair();
      const badPub = await exportPublicKey(bad.publicKey);

      const e1 = await prepareAppendEventEnvelope(good.privateKey, goodPub, { n: 1 }, symKey);
      const e2 = await prepareAppendEventEnvelope(bad.privateKey, badPub, { n: 2 }, symKey);

      const raw = [
        { ...e1, id: "1" },
        { ...e2, id: "2" }
      ];

      const filtered = await processLedgerEventSnapshot(raw, symKey, {
        authorizedSigners: new Set([goodPub])
      });
      expect(filtered.length).toBe(1);
      expect(filtered[0].action).toEqual({ n: 1 });
    });
  });

  // ──────────────────────────────────────────────────────────────────
  // Snapshot memoization cache
  // ──────────────────────────────────────────────────────────────────
  it("processLedgerEventSnapshot reuses cached results instead of re-decrypting", async () => {
    const symKey = await generateSymmetricKey(256);
    const wrongKey = await generateSymmetricKey(256);
    const signer = await generateIdentityKeyPair();
    const signerPub = await exportPublicKey(signer.publicKey);

    const env = await prepareAppendEventEnvelope(signer.privateKey, signerPub, { hello: "world" }, symKey);
    const raw = [{ ...env, id: "evt-1" }];
    const cache = new Map();

    const first = await processLedgerEventSnapshot(raw, symKey, { cache });
    expect(first.length).toBe(1);

    // Second pass with the WRONG key but the same cache: a cache hit must return
    // the previously-decrypted event rather than re-decrypting (which would fail).
    const second = await processLedgerEventSnapshot(raw, wrongKey, { cache });
    expect(second.length).toBe(1);
    expect(second[0].action).toEqual({ hello: "world" });
  });

  // ──────────────────────────────────────────────────────────────────
  // Revocation purges the revoked device from ALL keyring versions
  // ──────────────────────────────────────────────────────────────────
  it("rotateKeys removes the revoked device from historical keyrings, not just the active one", async () => {
    const devA = await generateDeviceKeyPair();
    const devAPub = await exportDevicePublicKey(devA.publicKey);

    const devB = await generateDeviceKeyPair();
    const devBPub = await exportDevicePublicKey(devB.publicKey);
    const devBPriv = await exportDevicePrivateKey(devB.privateKey);

    const prfKey = await generateSymmetricKey(256);
    const { doc: genesis } = await prepareGenesisDocument("dev-a", "A", devAPub, "cred", prfKey, "prf-a");

    const amk = await generateSymmetricKey(256);
    const withB = await prepareRegistrationData(amk, "amk_v1", "B", "dev-b", devBPub, genesis);
    const rawAmk = await crypto.exportSymmetricKey(amk);
    withB.keyring["amk_v1"]["dev-b"] = await wrapAmk(devB.publicKey, rawAmk.buffer as ArrayBuffer);

    // Sanity: before rotation device B can unwrap amk_v1.
    await expect(unwrapAmkById(withB, "dev-b", devBPriv, "amk_v1")).resolves.toBeDefined();

    const newAmk = await generateSymmetricKey(256);
    const rotated = await rotateKeys("dev-b", withB, amk, newAmk, "amk_v2", prfKey);

    // The historical keyring entry for the revoked device must be gone (old code
    // only removed it from the NEW keyring version).
    expect(rotated.keyring["amk_v1"]?.["dev-b"]).toBeUndefined();
    expect(rotated.keyring["amk_v2"]?.["dev-b"]).toBeUndefined();
    await expect(unwrapAmkById(rotated, "dev-b", devBPriv, "amk_v1")).rejects.toThrow();

    // Still-authorized device A retains historical access.
    expect(rotated.keyring["amk_v1"]?.["dev-a"]).toBeDefined();
  });

  // ──────────────────────────────────────────────────────────────────
  // Untrusted envelope parsing
  // ──────────────────────────────────────────────────────────────────
  describe("parseEncryptedEnvelopeB64", () => {
    it("returns ciphertext/iv for a well-formed envelope", () => {
      const b64 = btoa(JSON.stringify({ ciphertext: "AAAA", iv: "BBBB" }));
      expect(parseEncryptedEnvelopeB64(b64)).toEqual({ ciphertext: "AAAA", iv: "BBBB" });
    });

    it("throws on non-base64 / non-JSON input", () => {
      expect(() => parseEncryptedEnvelopeB64("!!!not base64!!!")).toThrow("MALFORMED_ENVELOPE");
      expect(() => parseEncryptedEnvelopeB64(btoa("not json"))).toThrow("MALFORMED_ENVELOPE");
    });

    it("throws when required fields are missing or wrong-typed", () => {
      expect(() => parseEncryptedEnvelopeB64(btoa(JSON.stringify({ ciphertext: "x" })))).toThrow("MALFORMED_ENVELOPE");
      expect(() => parseEncryptedEnvelopeB64(btoa(JSON.stringify({ ciphertext: 1, iv: 2 })))).toThrow("MALFORMED_ENVELOPE");
      expect(() => parseEncryptedEnvelopeB64(btoa(JSON.stringify(null)))).toThrow("MALFORMED_ENVELOPE");
    });
  });

  // ──────────────────────────────────────────────────────────────────
  // canonicalStringify must escape keys to avoid signature collisions
  // ──────────────────────────────────────────────────────────────────
  it("canonicalStringify escapes keys so structurally-distinct objects cannot collide", () => {
    // Under the old `"${key}"` interpolation these two produced identical output
    // ({"a":1,"b":2}) — a signature-canonicalization collision.
    const obj1 = { a: 1, b: 2 };
    const obj2 = { 'a":1,"b': 2 };
    expect(canonicalStringify(obj1)).not.toBe(canonicalStringify(obj2));
    // Output remains valid JSON.
    expect(() => JSON.parse(canonicalStringify(obj2))).not.toThrow();
  });
});
