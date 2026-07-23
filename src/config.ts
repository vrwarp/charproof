import type { Firestore } from "firebase/firestore";
import type { Auth } from "firebase/auth";
import { setCryptoProvider } from "./core/crypto";
import { WebCryptoProvider } from "./browser/WebCryptoProvider";
import { setPrfProviders } from "./prfService";
import { WebAuthnPrfProvider, type WebAuthnPrfOptions } from "./browser/WebAuthnPrfProvider";
import type { CryptoProvider, PrfProvider } from "./core/interfaces";

let db: Firestore | null = null;
let auth: Auth | null = null;

export interface InitializeZKConfig {
  db: Firestore;
  auth: Auth;
  /**
   * Optional cryptographic provider override. Defaults to the browser's
   * WebCrypto-backed provider. Supply a custom provider ONLY for testing — this
   * is the single, explicit injection point. There is intentionally no ambient
   * (e.g. `window`-global) switch: a runtime-toggleable mock in the production
   * crypto path would let any XSS/extension downgrade encryption to plaintext.
   */
  cryptoProvider?: CryptoProvider;
  /** Optional WebAuthn PRF provider override (testing only). */
  prfProvider?: PrfProvider;
  /**
   * Optional configuration for the built-in WebAuthn PRF provider — relying-party
   * name/id, PRF salt, and userVerification. Ignored when a custom `prfProvider`
   * instance is supplied. See {@link WebAuthnPrfOptions}; `prfSalt`, `rpId`, and
   * `userVerification` are effectively set-once per deployment.
   */
  prf?: WebAuthnPrfOptions;
}

export function initializeZK(config: InitializeZKConfig) {
  db = config.db;
  auth = config.auth;

  setCryptoProvider(config.cryptoProvider ?? new WebCryptoProvider());

  if (config.prfProvider) {
    setPrfProviders({ prfProvider: config.prfProvider });
  } else if (config.prf) {
    setPrfProviders({ prfProvider: new WebAuthnPrfProvider(config.prf) });
  }
}

export function getDb(): Firestore {
  if (!db) {
    throw new Error("ZeroKnowledge library has not been initialized. Call initializeZK({ db, auth }) first.");
  }
  return db;
}

export function getAuth(): Auth {
  if (!auth) {
    throw new Error("ZeroKnowledge library has not been initialized. Call initializeZK({ db, auth }) first.");
  }
  return auth;
}
