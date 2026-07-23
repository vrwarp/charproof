import type { PrfProvider } from "../core/interfaces";

/** Default PRF evaluation salt. Preserved from earlier versions so existing
 *  sealed credentials keep deriving the same key. */
const DEFAULT_PRF_SALT = "LetUsMeet-PRF-Salt-v1";
/** Default relying-party display name. Display-only (see WebAuthnPrfOptions). */
const DEFAULT_RP_NAME = "LetUsMeet";
/** Default user-verification posture. See WebAuthnPrfOptions.userVerification. */
const DEFAULT_UV: UserVerificationRequirement = "preferred";

export interface WebAuthnPrfOptions {
  /**
   * Relying-party display name shown in the OS passkey prompt (`rp.name`).
   * Display-only — it does not scope credentials, so it is safe to change at any
   * time. Default: "LetUsMeet".
   */
  rpName?: string;
  /**
   * Relying-party ID (`rp.id`) — scopes which credentials are discoverable.
   * Leave undefined to let the browser default it to the current origin's
   * effective domain. WARNING: changing this after credentials exist strands
   * them (they will no longer be found), so treat it as set-once per deployment.
   */
  rpId?: string;
  /**
   * PRF evaluation salt (the `prf.eval.first` input), as raw bytes or a UTF-8
   * string. The derived key is a function of this salt, so a different value
   * derives a DIFFERENT key and cannot unwrap any previously-sealed AMK.
   * Effectively set-once per deployment. Default: UTF-8 bytes of
   * "LetUsMeet-PRF-Salt-v1".
   */
  prfSalt?: Uint8Array | string;
  /**
   * User-verification requirement, applied IDENTICALLY to `create()` and
   * `get()`.
   *
   * WebAuthn PRF rides on CTAP2 `hmac-secret`, which keeps two per-credential
   * secrets (`CredRandomWithUV` / `CredRandomWithoutUV`) and returns one based
   * on whether user verification was *actually performed* during the ceremony.
   * Evaluating with UV in one ceremony and without it in another therefore
   * derives DIFFERENT keys and silently breaks decryption. To keep the key
   * stable this is a single value used for both ceremonies — never a per-op
   * setting and never an escalation ladder.
   *
   * Default "preferred": on platform authenticators (Android Google Password
   * Manager, Touch ID, Windows Hello) UV is always performed, so PRF is
   * provisioned/evaluated and the derived key is stable. Use "required" if you
   * support roaming security keys that can skip UV — it forces uv=1 on every
   * ceremony, guaranteeing key stability at the cost of failing UV-incapable
   * authenticators. "discouraged" reproduces the legacy behavior and fails to
   * yield PRF on Android GPM.
   *
   * FORWARD-COMPATIBILITY CAVEAT (roaming security keys only): "preferred" is
   * non-deterministic — the authenticator decides whether to perform UV. On a
   * platform authenticator that is always uv=1, so the key is stable. But on a
   * roaming key that starts WITHOUT a PIN and later HAS one configured, the same
   * "preferred" request can flip from uv=0 (CredRandomWithoutUV) at seal time to
   * uv=1 (CredRandomWithUV) at recovery time, deriving a DIFFERENT key and
   * silently breaking recovery. If your users may enroll PRF on roaming keys,
   * pin "required" (deterministic uv=1) instead of relying on this default.
   */
  userVerification?: UserVerificationRequirement;
}

/**
 * Thrown when an authenticator ceremony completed but returned no PRF result.
 * Typed (rather than a bare Error with a magic message) so callers can branch —
 * e.g. genesis falling back to a non-PRF recovery custodian — via `instanceof`
 * instead of string-matching.
 */
export class PrfUnavailableError extends Error {
  readonly credentialIds: string[];
  readonly userVerification: UserVerificationRequirement;

  constructor(userVerification: UserVerificationRequirement, credentialIds: string[] = []) {
    super("PRF evaluation failed or not supported by authenticator.");
    this.name = "PrfUnavailableError";
    this.credentialIds = credentialIds;
    this.userVerification = userVerification;
    // Preserve `instanceof` across transpilation targets that break subclassing.
    Object.setPrototypeOf(this, PrfUnavailableError.prototype);
  }
}

export class WebAuthnPrfProvider implements PrfProvider {
  private readonly rpName: string;
  private readonly rpId?: string;
  private readonly prfSalt: Uint8Array;
  private readonly userVerification: UserVerificationRequirement;

  constructor(options: WebAuthnPrfOptions = {}) {
    this.rpName = options.rpName ?? DEFAULT_RP_NAME;
    this.rpId = options.rpId;
    this.prfSalt =
      options.prfSalt === undefined
        ? new TextEncoder().encode(DEFAULT_PRF_SALT)
        : typeof options.prfSalt === "string"
          ? new TextEncoder().encode(options.prfSalt)
          : new Uint8Array(options.prfSalt);
    this.userVerification = options.userVerification ?? DEFAULT_UV;
  }

  /** Fresh PRF extension object each call — some UAs neuter the salt buffer, so
   *  we never share a reference across ceremonies. */
  private prfExtension() {
    return { prf: { eval: { first: this.prfSalt.slice() } } } as any;
  }

  async createCredential(
    userId: string,
    userName: string,
    displayName: string
  ): Promise<{ credentialId: string; prfResult: Uint8Array }> {
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const rp: PublicKeyCredentialRpEntity = { name: this.rpName };
    if (this.rpId) rp.id = this.rpId;

    const createOptions: CredentialCreationOptions = {
      publicKey: {
        challenge,
        rp,
        user: {
          id: new TextEncoder().encode(userId),
          name: userName,
          displayName: displayName
        },
        pubKeyCredParams: [
          { alg: -7, type: "public-key" },
          { alg: -257, type: "public-key" }
        ],
        authenticatorSelection: { userVerification: this.userVerification },
        extensions: this.prfExtension()
      }
    };

    const credential = (await navigator.credentials.create(createOptions)) as any;
    if (!credential) throw new Error("Failed to create PRF credential.");

    const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));

    const results = credential.getClientExtensionResults();
    if (results.prf && results.prf.results && results.prf.results.first) {
      const prfResult = new Uint8Array(results.prf.results.first);
      return { credentialId, prfResult };
    }

    // Android / Google Password Manager returns `prf: { enabled: true }` with no
    // `results` at creation time. Evaluate via a follow-up assertion on the
    // just-created credential, using the SAME userVerification so the PRF value
    // matches what a later recovery `get()` will derive.
    const assertion = await this.getAssertion([credentialId]);
    return { credentialId, prfResult: assertion.prfResult };
  }

  async getAssertion(
    credentialIds: string[]
  ): Promise<{ usedCredentialId: string; prfResult: Uint8Array }> {
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge,
      allowCredentials: credentialIds.map(id => ({
        id: Uint8Array.from(atob(id), c => c.charCodeAt(0)),
        type: "public-key" as const
      })),
      userVerification: this.userVerification,
      extensions: this.prfExtension()
    };
    if (this.rpId) publicKey.rpId = this.rpId;

    const assertion = (await navigator.credentials.get({ publicKey })) as any;
    const results = assertion.getClientExtensionResults();

    if (!results.prf || !results.prf.results || !results.prf.results.first) {
      throw new PrfUnavailableError(this.userVerification, credentialIds);
    }

    const prfResult = new Uint8Array(results.prf.results.first);
    const usedCredentialId = btoa(String.fromCharCode(...new Uint8Array(assertion.rawId)));
    return { usedCredentialId, prfResult };
  }
}
