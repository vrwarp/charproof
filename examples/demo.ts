/**
 * Charproof - Zero-Knowledge Encryption and Identity Management Library Demo
 * 
 * This example application acts as both a step-by-step walkthrough of the library's
 * core ZK capabilities and a robust integration test runner. It demonstrates how to
 * perform zero-knowledge operations on multiple mock devices.
 * 
 * --- CRYPTOGRAPHIC CONCEPT SUMMARY FOR JUNIOR ENGINEERS ---
 * 
 * 1. Account Master Key (AMK):
 *    This is the root symmetric key (AES-256) owned by the user. It NEVER leaves the user's
 *    device in plaintext. It is used to encrypt/decrypt sensitive credentials stored in the
 *    shared database (Cloud Keystore).
 * 
 * 2. Device Keyrings:
 *    Every enrolled device (e.g. Mac, iPhone) has its own local asymmetric keypair (RSA-OAEP).
 *    The shared database holds a keyring mapping device IDs to the active AMK *wrapped* (encrypted)
 *    using each device's individual public key. Thus, any authorized device can decrypt the AMK,
 *    but the server/database cannot.
 * 
 * 3. Client-Side Decryption:
 *    Ledger session keys are symmetrically encrypted using the active AMK and stored in the Keystore.
 *    Devices fetch this wrapped session key, decrypt it using the AMK, and then decrypt individual
 *    ledger events locally.
 */

import {
  setCryptoProvider,
  setDeviceServiceProviders,
  setPrfProviders,
  setSessionProviders,
  setRecoveryProviders,
  getActiveAmk,
  createLedgerSession,
  getLedgerSession,
  requestDeviceAuthorization,
  approveDeviceAuthorization,
  setupPhraseRecovery,
  recoverAmkWithPhrase,
  loadFromKeystore
} from "../src/index";

// Import fully functional deterministic mocks designed for testing browser environments in Node
import {
  DeterministicCryptoProvider,
  MockAccountKeyStore,
  MockLocalDeviceStore,
  MockAuthProvider,
  MockPrfProvider,
  MockLedgerEventStore
} from "../src/core/__tests__/DeterministicMocks";

// Polyfill browser IndexedDB capability in Node.js
import "fake-indexeddb/auto";

// --- BROWSER API POLYFILLS ---
// Since the library targets browser environments (which have `localStorage` natively),
// we polyfill a simple in-memory `localStorage` so the code runs perfectly in Node CLI.
const store = new Map<string, string>();
const localStorageMock = {
  getItem: (key: string): string | null => store.has(key) ? store.get(key)! : null,
  setItem: (key: string, value: string): void => { store.set(key, String(value)); },
  removeItem: (key: string): void => { store.delete(key); },
  clear: (): void => { store.clear(); },
  key: (index: number): string | null => Array.from(store.keys())[index] || null,
  get length() { return store.size; }
};
Object.defineProperty(globalThis, "localStorage", {
  value: localStorageMock,
  writable: true,
  configurable: true
});

// Style helpers for clean, beautifully colored console logs
const colors = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  red: "\x1b[31m",
  bold: "\x1b[1m"
};

/** Prints a bold visual stage separator */
function header(title: string) {
  console.log(`\n${colors.bold}${colors.magenta}=== ${title} ===${colors.reset}`);
}

/** Prints informational logs */
function log(step: string, detail?: any) {
  console.log(`${colors.cyan}ℹ [INFO]${colors.reset} ${step}`);
  if (detail) {
    console.log(`${colors.blue}  ↳ ${JSON.stringify(detail, null, 2)}${colors.reset}`);
  }
}

/** Prints successful step verifications */
function success(message: string) {
  console.log(`${colors.green}✔ [SUCCESS] ${message}${colors.reset}`);
}

async function runDemo() {
  header("INITIALIZING CHARPROOF DEMO & INTEGRATION TEST");

  // 1. Setup shared global components (Database, Cryptography, and PRF Provider mocks)
  const cryptoProvider = new DeterministicCryptoProvider(42);
  const accountKeyStore = new MockAccountKeyStore(); // Simulates Firestore Account Keystore
  const eventStore = new MockLedgerEventStore();     // Simulates Firestore Ledger Events Store
  const prfProvider = new MockPrfProvider();         // Simulates WebAuthn Hardware Passkeys

  // Inject the core Cryptographic implementation
  setCryptoProvider(cryptoProvider);

  // ----------------------------------------------------
  header("STAGE 1: DEVICE A GENESIS FLOW");
  // ----------------------------------------------------
  // Device A acts as the user's primary device (e.g. Alice's Mac)
  const devA_Store = new MockLocalDeviceStore("device-a", "Alice's Mac");
  const authA = new MockAuthProvider();
  authA.currentUser = {
    uid: "user-123",
    isAnonymous: false,
    email: "alice@example.com",
    displayName: "Alice"
  };

  // Configure providers specifically for Device A.
  // We use dependency injection to dynamically define context per-device during tests/demo.
  setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devA_Store, authProvider: authA });
  setPrfProviders({ localDeviceStore: devA_Store, authProvider: authA, prfProvider });
  setSessionProviders({ ledgerEventStore: eventStore, accountKeyStore, localDeviceStore: devA_Store, authProvider: authA });
  setRecoveryProviders({ accountKeyStore, localDeviceStore: devA_Store, authProvider: authA });

  log("Requesting active AMK on fresh account (Genesis)...");
  // This triggers key generation for a fresh account. It creates the AMK and stores
  // a keyring containing the AMK wrapped by Device A's local public key.
  const activeAmkA = await getActiveAmk();
  success(`Active AMK created. ID: ${activeAmkA.amkId}`);

  log("Creating a new client-side encrypted ledger session...");
  // Generates a random session symmetric key and registers the ledger session.
  // The session key is encrypted with the active AMK and stored in the Cloud Keystore.
  const { session: sessionA, ledgerId, ownershipToken } = await createLedgerSession();
  success(`Ledger session created. Ledger ID: ${ledgerId}`);

  log("Appending a zero-knowledge encrypted GENESIS event...");
  // All events appended to the ledger are encrypted client-side using WebCrypto
  // before sending to the shared event store.
  await sessionA.appendEvent({ type: "GENESIS" });

  log("Appending an encrypted custom event (Vote)...");
  const votePayload = { type: "VOTE", optionId: "option-1" };
  await sessionA.appendEvent(votePayload);
  success("Events encrypted and written to event store.");

  // ----------------------------------------------------
  header("STAGE 2: MULTI-DEVICE ENROLLMENT FLOW (DEVICE B)");
  // ----------------------------------------------------
  // Device B acts as the user's secondary device (e.g. Alice's iPhone)
  const devB_Store = new MockLocalDeviceStore("device-b", "Alice's iPhone");
  const authB = new MockAuthProvider();
  authB.currentUser = { ...authA.currentUser }; // Logged in as the same user

  // Switch context to Device B
  log("Switching environment to Device B (unauthorized device)...");
  setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider: authB });
  setPrfProviders({ localDeviceStore: devB_Store, authProvider: authB, prfProvider });
  setSessionProviders({ ledgerEventStore: eventStore, accountKeyStore, localDeviceStore: devB_Store, authProvider: authB });

  log("Device B requesting access to Alice's account...");
  // Device B generates its local RSA keypair, registers its public key in the
  // database, and requests authorization from primary devices.
  await requestDeviceAuthorization();
  const pendingDevice = await accountKeyStore.getPendingDevice("device-b");
  log("Pending authorization request registered:", {
    deviceId: pendingDevice?.deviceId,
    deviceName: pendingDevice?.deviceName,
    status: pendingDevice?.status
  });

  // Switch context back to Device A to approve the request
  log("Switching back to Device A to approve request...");
  setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devA_Store, authProvider: authA });
  
  if (!pendingDevice) throw new Error("Pending device B not found in registry!");
  // Device A reads Device B's public key, decrypts the AMK locally, re-encrypts
  // the AMK using Device B's public key, and updates the shared keyring.
  await approveDeviceAuthorization(pendingDevice);
  success("Device A approved Device B's authorization request.");

  // Switch context back to Device B
  log("Switching back to Device B...");
  setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider: authB });
  setPrfProviders({ localDeviceStore: devB_Store, authProvider: authB, prfProvider });
  setSessionProviders({ ledgerEventStore: eventStore, accountKeyStore, localDeviceStore: devB_Store, authProvider: authB });

  log("Device B attempting to retrieve the active AMK...");
  // Device B fetches the updated keyring, decrypts the AMK segment using its
  // local RSA private key, and stores the active AMK in memory.
  const activeAmkB = await getActiveAmk();
  success(`Device B successfully derived active AMK! ID: ${activeAmkB.amkId}`);

  // Assert both derived AMKs match (proves successful key sharing)
  if (activeAmkB.amkId !== activeAmkA.amkId) {
    throw new Error("Active AMK ID mismatch between Device A and Device B!");
  }

  // ----------------------------------------------------
  header("STAGE 3: CLIENT-SIDE DECRYPTION ON DEVICE B");
  // ----------------------------------------------------
  log("Device B retrieving credentials and initializing ledger session...");
  // Load the wrapped ledger session key from Cloud Keystore
  const creds = await loadFromKeystore(ledgerId);
  if (!creds) throw new Error("Could not load credentials from keystore!");

  // Initialize the session locally. The library automatically uses the derived AMK
  // to decrypt the session key.
  const sessionB = await getLedgerSession(ledgerId, {
    shareableKey: creds.symmetricKey
  });

  log("Subscribing and decrypting events from the ledger...");
  let decryptedEvents: any[] = [];
  const unsubscribe = sessionB.subscribe((events) => {
    // Decrypts each event retrieved from the database on-the-fly
    decryptedEvents = events;
  });

  // Small delay to simulate async decryption and state machine updates
  await new Promise((resolve) => setTimeout(resolve, 50));
  unsubscribe();

  log("Decrypted events on Device B:", decryptedEvents.map(e => e.action));

  // Assert events decrypted correctly
  if (decryptedEvents.length !== 2) {
    throw new Error(`Expected 2 events, but decrypted ${decryptedEvents.length}`);
  }

  const decryptedVote = decryptedEvents[1].action;
  if (decryptedVote.type !== "VOTE" || decryptedVote.optionId !== "option-1") {
    throw new Error("Decrypted event payload mismatch!");
  }
  success("Device B successfully decrypted and verified Alice's original vote event!");

  // ----------------------------------------------------
  header("STAGE 4: MNEMONIC RECOVERY FLOW (DEVICE C)");
  // ----------------------------------------------------
  // Switch back to Device A to setup phrase-based recovery
  log("Switching back to Device A to configure recovery phrase...");
  setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devA_Store, authProvider: authA });
  setRecoveryProviders({ accountKeyStore, localDeviceStore: devA_Store, authProvider: authA });

  log("Generating new recovery phrase...");
  // Generates a 24-word BIP39 mnemonic, derives an AES key from it, and encrypts
  // a new recovery RSA keypair, storing the wrapped AMK in the keyring.
  const phrase = await setupPhraseRecovery();
  log(`Mnemonic Recovery Phrase generated: "${phrase}"`);

  // Switch to clean, completely unregistered Device C (e.g. Alice's new iPad)
  log("Switching to clean, unregistered Device C...");
  const devC_Store = new MockLocalDeviceStore("device-c", "Alice's iPad");
  const authC = new MockAuthProvider();
  authC.currentUser = { ...authA.currentUser };

  setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devC_Store, authProvider: authC });
  setRecoveryProviders({ accountKeyStore, localDeviceStore: devC_Store, authProvider: authC });

  log("Recovering the active AMK on Device C using the mnemonic phrase...");
  // Derives the symmetric protector from the mnemonic using PBKDF2, decrypts the
  // recovery RSA private key, and uses it to unwrap the active AMK.
  const recoveredAmk = await recoverAmkWithPhrase(phrase);
  success(`Device C successfully recovered AMK! ID: ${recoveredAmk.amkId}`);

  // Assert recovered AMK is correct
  if (recoveredAmk.amkId !== activeAmkA.amkId) {
    throw new Error("Recovered AMK ID mismatch!");
  }

  // ----------------------------------------------------
  header("DEMO COMPLETE - ALL ZERO-KNOWLEDGE LIFECYCLES VERIFIED");
  // ----------------------------------------------------
  console.log(`\n${colors.bold}${colors.green}★ INTEGRATION TEST STATUS: PASSED ★${colors.reset}\n`);
}

runDemo().catch((err) => {
  console.error(`\n${colors.bold}${colors.red}❌ DEMO FAILED: ${err.message}${colors.reset}\n`);
  process.exit(1);
});
