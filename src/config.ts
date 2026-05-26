import type { Firestore } from "firebase/firestore";
import type { Auth } from "firebase/auth";
import { setCryptoProvider } from "./core/crypto";
import { WebCryptoProvider } from "./browser/WebCryptoProvider";
import { MockCryptoProvider } from "./mock/MockCryptoProvider";
import { MockPrfProvider } from "./mock/MockPrfProvider";
import { FirestoreAccountKeyStore } from "./browser/FirestoreAccountKeyStore";
import { setPrfProviders } from "./prfService";
import { setDeviceServiceProviders } from "./deviceService";

let db: Firestore | null = null;
let auth: Auth | null = null;

export function initializeZK(config: { db: Firestore; auth: Auth }) {
  db = config.db;
  auth = config.auth;
  const isMockMode =
    (typeof window !== "undefined" && (window as any).__MOCK_ZK === "true");

  if (isMockMode) {
    console.warn("⚠️ DEBUG: Zero-Knowledge package running in MOCK mode.");
    setCryptoProvider(new MockCryptoProvider());
    setPrfProviders({ prfProvider: new MockPrfProvider() });
    setDeviceServiceProviders({ accountKeyStore: new FirestoreAccountKeyStore() });
  } else {
    // Automatically initialize browser-based WebCryptoProvider
    setCryptoProvider(new WebCryptoProvider());
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
