import type { Firestore } from "firebase/firestore";
import type { Auth } from "firebase/auth";
import { setCryptoProvider } from "./core/crypto";
import { WebCryptoProvider } from "./browser/WebCryptoProvider";
import { setPrfProviders } from "./prfService";
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
}

export function initializeZK(config: InitializeZKConfig) {
  db = config.db;
  auth = config.auth;

  setCryptoProvider(config.cryptoProvider ?? new WebCryptoProvider());

  if (config.prfProvider) {
    setPrfProviders({ prfProvider: config.prfProvider });
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
