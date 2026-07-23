import { describe, test, expect, beforeEach, afterEach, vi } from "vitest";
import { WebAuthnPrfProvider, PrfUnavailableError } from "./WebAuthnPrfProvider";

/** ASCII string → the bytes a WebAuthn `rawId` would carry. */
function rawId(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}
/** The credentialId the provider derives from a rawId (base64 of the bytes). */
function b64(str: string): string {
  return btoa(str);
}

describe("WebAuthnPrfProvider", () => {
  let createCalls: any[];
  let getCalls: any[];
  let createImpl: (opts: any) => any;
  let getImpl: (opts: any) => any;

  beforeEach(() => {
    createCalls = [];
    getCalls = [];
    createImpl = () => {
      throw new Error("createImpl not configured");
    };
    getImpl = () => {
      throw new Error("getImpl not configured");
    };

    vi.stubGlobal("window", { crypto: globalThis.crypto });
    vi.stubGlobal("navigator", {
      credentials: {
        create: async (opts: any) => {
          createCalls.push(opts);
          return createImpl(opts);
        },
        get: async (opts: any) => {
          getCalls.push(opts);
          return getImpl(opts);
        }
      }
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test("create() that yields PRF at creation time does not call get(); default UV is 'discouraged'", async () => {
    const prf = new Uint8Array(32).fill(7);
    createImpl = () => ({
      rawId: rawId("cred-1"),
      getClientExtensionResults: () => ({ prf: { results: { first: prf } } })
    });

    const provider = new WebAuthnPrfProvider();
    const res = await provider.createCredential("uid", "name", "display");

    expect(getCalls.length).toBe(0);
    expect(createCalls[0].publicKey.authenticatorSelection.userVerification).toBe("discouraged");
    expect(createCalls[0].publicKey.rp.name).toBe("LetUsMeet");
    expect(createCalls[0].publicKey.rp.id).toBeUndefined();
    expect(res.credentialId).toBe(b64("cred-1"));
    expect(Array.from(res.prfResult)).toEqual(Array.from(prf));
  });

  test("Android path: create() returns enabled/no-results → falls back to get() with the SAME userVerification", async () => {
    createImpl = () => ({
      rawId: rawId("cred-2"),
      getClientExtensionResults: () => ({ prf: { enabled: true } })
    });
    const getPrf = new Uint8Array(32).fill(9);
    getImpl = () => ({
      rawId: rawId("cred-2"),
      getClientExtensionResults: () => ({ prf: { results: { first: getPrf } } })
    });

    const provider = new WebAuthnPrfProvider();
    const res = await provider.createCredential("uid", "name", "display");

    expect(getCalls.length).toBe(1);
    // Key-stability invariant: create and get MUST request the same UV, else the
    // authenticator could pick a different hmac-secret and derive a different key.
    const createUv = createCalls[0].publicKey.authenticatorSelection.userVerification;
    const getUv = getCalls[0].publicKey.userVerification;
    expect(createUv).toBe("discouraged");
    expect(getUv).toBe(createUv);
    expect(res.credentialId).toBe(b64("cred-2"));
    expect(Array.from(res.prfResult)).toEqual(Array.from(getPrf));
  });

  test("get() with no PRF result throws a typed PrfUnavailableError carrying context", async () => {
    getImpl = () => ({
      rawId: rawId("cred-3"),
      getClientExtensionResults: () => ({}) // authenticator returned nothing
    });

    const provider = new WebAuthnPrfProvider({ userVerification: "required" });
    const ids = [b64("cred-3")];

    await expect(provider.getAssertion(ids)).rejects.toBeInstanceOf(PrfUnavailableError);
    try {
      await provider.getAssertion(ids);
      throw new Error("should have thrown");
    } catch (e: any) {
      expect(e).toBeInstanceOf(PrfUnavailableError);
      expect(e.name).toBe("PrfUnavailableError");
      expect(e.userVerification).toBe("required");
      expect(e.credentialIds).toEqual(ids);
    }
  });

  test("get() success returns the used credential id and PRF value; rpId is forwarded when configured", async () => {
    const prf = new Uint8Array(32).fill(4);
    getImpl = () => ({
      rawId: rawId("used-cred"),
      getClientExtensionResults: () => ({ prf: { results: { first: prf } } })
    });

    const provider = new WebAuthnPrfProvider({ rpId: "example.com" });
    const res = await provider.getAssertion([b64("cred-x")]);

    expect(getCalls[0].publicKey.rpId).toBe("example.com");
    expect(getCalls[0].publicKey.userVerification).toBe("discouraged");
    expect(res.usedCredentialId).toBe(b64("used-cred"));
    expect(Array.from(res.prfResult)).toEqual(Array.from(prf));
  });

  test("options override rpName/rpId/prfSalt/userVerification in the WebAuthn request", async () => {
    const prf = new Uint8Array(32).fill(3);
    createImpl = () => ({
      rawId: rawId("c"),
      getClientExtensionResults: () => ({ prf: { results: { first: prf } } })
    });

    const provider = new WebAuthnPrfProvider({
      rpName: "MyApp",
      rpId: "example.com",
      prfSalt: "custom-salt",
      userVerification: "required"
    });
    await provider.createCredential("u", "n", "d");

    const pk = createCalls[0].publicKey;
    expect(pk.rp.name).toBe("MyApp");
    expect(pk.rp.id).toBe("example.com");
    expect(pk.authenticatorSelection.userVerification).toBe("required");
    expect(new TextDecoder().decode(new Uint8Array(pk.extensions.prf.eval.first))).toBe("custom-salt");
  });

  test("default PRF salt is unchanged from the legacy value (credential compatibility)", async () => {
    const prf = new Uint8Array(32).fill(1);
    createImpl = () => ({
      rawId: rawId("c"),
      getClientExtensionResults: () => ({ prf: { results: { first: prf } } })
    });

    const provider = new WebAuthnPrfProvider();
    await provider.createCredential("u", "n", "d");

    const salt = new TextDecoder().decode(
      new Uint8Array(createCalls[0].publicKey.extensions.prf.eval.first)
    );
    expect(salt).toBe("LetUsMeet-PRF-Salt-v1");
  });

  test("accepts a Uint8Array prfSalt as-is", async () => {
    const prf = new Uint8Array(32).fill(1);
    getImpl = () => ({
      rawId: rawId("c"),
      getClientExtensionResults: () => ({ prf: { results: { first: prf } } })
    });
    const saltBytes = new Uint8Array([1, 2, 3, 4, 5]);

    const provider = new WebAuthnPrfProvider({ prfSalt: saltBytes });
    await provider.getAssertion([b64("cred")]);

    expect(Array.from(new Uint8Array(getCalls[0].publicKey.extensions.prf.eval.first))).toEqual([
      1, 2, 3, 4, 5
    ]);
  });

  test("create() requests a discoverable credential by default (routes to GPM on Android)", async () => {
    const prf = new Uint8Array(32).fill(2);
    createImpl = () => ({
      rawId: rawId("c"),
      getClientExtensionResults: () => ({ prf: { results: { first: prf } } })
    });

    const provider = new WebAuthnPrfProvider();
    await provider.createCredential("u", "n", "d");

    const sel = createCalls[0].publicKey.authenticatorSelection;
    expect(sel.residentKey).toBe("required");
    expect(sel.requireResidentKey).toBe(true); // legacy alias
    // No attachment restriction by default → resident-capable roaming keys still work.
    expect(sel.authenticatorAttachment).toBeUndefined();
  });

  test("residentKey/authenticatorAttachment are configurable; 'preferred' clears the legacy alias", async () => {
    const prf = new Uint8Array(32).fill(2);
    createImpl = () => ({
      rawId: rawId("c"),
      getClientExtensionResults: () => ({ prf: { results: { first: prf } } })
    });

    const provider = new WebAuthnPrfProvider({
      residentKey: "preferred",
      authenticatorAttachment: "platform"
    });
    await provider.createCredential("u", "n", "d");

    const sel = createCalls[0].publicKey.authenticatorSelection;
    expect(sel.residentKey).toBe("preferred");
    expect(sel.requireResidentKey).toBe(false);
    expect(sel.authenticatorAttachment).toBe("platform");
  });

  test("get() carries no authenticatorSelection/residentKey (discoverability is creation-only)", async () => {
    const prf = new Uint8Array(32).fill(2);
    getImpl = () => ({
      rawId: rawId("c"),
      getClientExtensionResults: () => ({ prf: { results: { first: prf } } })
    });

    const provider = new WebAuthnPrfProvider();
    await provider.getAssertion([b64("cred")]);

    expect(getCalls[0].publicKey.authenticatorSelection).toBeUndefined();
    expect(getCalls[0].publicKey.residentKey).toBeUndefined();
  });

  test("create() short-circuits to PrfUnavailableError when the authenticator reports prf.enabled === false", async () => {
    createImpl = () => ({
      rawId: rawId("no-prf"),
      getClientExtensionResults: () => ({ prf: { enabled: false } })
    });

    const provider = new WebAuthnPrfProvider();
    await expect(provider.createCredential("u", "n", "d")).rejects.toBeInstanceOf(PrfUnavailableError);
    // Must NOT waste a follow-up assertion ceremony when PRF is explicitly unsupported.
    expect(getCalls.length).toBe(0);
  });
});
