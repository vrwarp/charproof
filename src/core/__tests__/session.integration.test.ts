import { describe, test, expect, beforeEach } from "vitest";
import { setCryptoProvider } from "../../core/crypto";
import {
  setSessionProviders,
  setDeviceServiceProviders,
  setPrfProviders,
  createLedgerSession,
  getLedgerSession,
  clearAmkSessionCache,
  clearPrfSessionCache,
  getActiveAmk,
  loadFromKeystore
} from "../../index";
import {
  DeterministicCryptoProvider,
  MockAccountKeyStore,
  MockLocalDeviceStore,
  MockAuthProvider,
  MockPrfProvider,
  MockLedgerEventStore
} from "./DeterministicMocks";
import type { DecryptedLedgerEvent } from "../../core/types";

describe("session Integration Tests", () => {
  let cryptoProvider: DeterministicCryptoProvider;
  let eventStore: MockLedgerEventStore;
  let accountKeyStore: MockAccountKeyStore;
  let localDeviceStore: MockLocalDeviceStore;
  let authProvider: MockAuthProvider;
  let prfProvider: MockPrfProvider;

  function resetAllCaches() {
    clearAmkSessionCache();
    clearPrfSessionCache();
  }

  beforeEach(() => {
    cryptoProvider = new DeterministicCryptoProvider(101);
    eventStore = new MockLedgerEventStore();
    accountKeyStore = new MockAccountKeyStore();
    localDeviceStore = new MockLocalDeviceStore("device-a", "Alice's Mac");
    authProvider = new MockAuthProvider();
    prfProvider = new MockPrfProvider();

    setCryptoProvider(cryptoProvider);
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore, authProvider });
    setPrfProviders({ localDeviceStore, authProvider, prfProvider });
    setSessionProviders({ ledgerEventStore: eventStore, accountKeyStore, localDeviceStore, authProvider });
    resetAllCaches();

    // Default setup: signed in user
    authProvider.currentUser = {
      uid: "user-123",
      isAnonymous: false,
      email: "user@example.com",
      displayName: "Alice"
    };
  });

  test("createLedgerSession saves credentials to keystore for signed in users", async () => {
    // Prime Device A active AMK
    await getActiveAmk();

    const { session, ownershipToken, ledgerId } = await createLedgerSession();
    expect(ledgerId).toBeDefined();
    expect(ownershipToken).toBeDefined();
    expect(session.exportSessionKey()).toBeDefined();

    // Verification: should be saved to Cloud Keystore and loadable
    const creds = await loadFromKeystore(ledgerId);
    expect(creds).not.toBeNull();
    expect(creds!.symmetricKey).toBe(session.exportSessionKey());
    expect(creds!.signingPublicKey).toBe(session.getSignerPublicKey());
  });

  test("createLedgerSession saves identity to local store for anonymous users", async () => {
    authProvider.currentUser = {
      uid: "anon-456",
      isAnonymous: true
    };

    const { session, ledgerId } = await createLedgerSession();

    // Verification: Cloud Keystore should be empty for this ledger
    const creds = await loadFromKeystore(ledgerId);
    expect(creds).toBeNull();

    // Verification: Local device store should have the identity
    const localIdentity = await localDeviceStore.loadIdentity(ledgerId);
    expect(localIdentity).not.toBeNull();
    expect(localIdentity!.publicKey).toBe(session.getSignerPublicKey());
  });

  test("getLedgerSession recovers from Keystore for signed in users", async () => {
    await getActiveAmk();

    const createRes = await createLedgerSession();
    
    // Clear caches and local session details
    resetAllCaches();

    // Retrieve ledger session
    const retrievedSession = await getLedgerSession(createRes.ledgerId);
    expect(retrievedSession.exportSessionKey()).toBe(createRes.session.exportSessionKey());
    expect(retrievedSession.getSignerPublicKey()).toBe(createRes.session.getSignerPublicKey());
  });

  test("getLedgerSession recovers from local store with shareableKey", async () => {
    // Anonymous user
    authProvider.currentUser = {
      uid: "anon-456",
      isAnonymous: true
    };

    const createRes = await createLedgerSession();
    const shareableKey = createRes.session.exportSessionKey();

    resetAllCaches();

    // Retrieve ledger session using local identity and shareable key
    const retrievedSession = await getLedgerSession(createRes.ledgerId, { shareableKey });
    expect(retrievedSession.exportSessionKey()).toBe(shareableKey);
    expect(retrievedSession.getSignerPublicKey()).toBe(createRes.session.getSignerPublicKey());
  });

  test("getLedgerSession recovers via ownershipToken", async () => {
    // 1. Owner creates the ledger anonymously and appends the genesis event
    authProvider.currentUser = {
      uid: "anon-456",
      isAnonymous: true
    };
    const createRes = await createLedgerSession();
    const shareableKey = createRes.session.exportSessionKey();
    const token = createRes.ownershipToken;

    // Owner must append the genesis event so it's written in the ledger event store
    await createRes.session.appendEvent({ type: "GENESIS" });

    // 2. Simulate owner logging into a new device (completely empty local store)
    const emptyLocalStore = new MockLocalDeviceStore("device-b", "Alice's Phone");
    setSessionProviders({ localDeviceStore: emptyLocalStore });

    // Try without shareableKey - should fail immediately
    await expect(getLedgerSession(createRes.ledgerId)).rejects.toThrow();

    // Recover using ownershipToken and shareableKey
    const recoveredSession = await getLedgerSession(createRes.ledgerId, {
      shareableKey,
      ownershipToken: token
    });
    expect(recoveredSession.exportSessionKey()).toBe(shareableKey);
    expect(recoveredSession.getSignerPublicKey()).toBe(createRes.session.getSignerPublicKey());

    // Identity should now be saved locally
    const recoveredIdentity = await emptyLocalStore.loadIdentity(createRes.ledgerId);
    expect(recoveredIdentity).not.toBeNull();
  });

  test("getLedgerSession creates a new participant identity when key provided", async () => {
    // 1. Creator creates ledger
    const createRes = await createLedgerSession();
    const shareableKey = createRes.session.exportSessionKey();

    // 2. Switch to a completely new participant (Device B, signed-in Bob)
    const bobLocalStore = new MockLocalDeviceStore("device-b", "Bob's Mac");
    const bobKeyStore = new MockAccountKeyStore();
    const bobAuth = new MockAuthProvider();
    bobAuth.currentUser = {
      uid: "bob-789",
      isAnonymous: false,
      email: "bob@example.com",
      displayName: "Bob"
    };

    setDeviceServiceProviders({
      localDeviceStore: bobLocalStore,
      accountKeyStore: bobKeyStore,
      authProvider: bobAuth
    });
    setSessionProviders({
      localDeviceStore: bobLocalStore,
      accountKeyStore: bobKeyStore,
      authProvider: bobAuth
    });

    // Bob doesn't have it in Keystore or local store. But he has the shareableKey!
    const bobSession = await getLedgerSession(createRes.ledgerId, { shareableKey });
    expect(bobSession.exportSessionKey()).toBe(shareableKey);
    expect(bobSession.getSignerPublicKey()).not.toBe(createRes.session.getSignerPublicKey());

    // Bob's generated identity should be saved locally
    const bobLocalIdentity = await bobLocalStore.loadIdentity(createRes.ledgerId);
    expect(bobLocalIdentity).not.toBeNull();
  });

  test("End-to-end ledger event append, encryption, signing, and subscription delivery", async () => {
    await getActiveAmk();
    const { session, ledgerId } = await createLedgerSession();

    let receivedEvents: DecryptedLedgerEvent[] = [];
    const unsubscribe = session.subscribe((events) => {
      receivedEvents = events;
    });

    // Owner appends the genesis event
    await session.appendEvent({ type: "GENESIS" });

    // Initial state: should contain the genesis event
    await new Promise(r => setTimeout(r, 50));
    expect(receivedEvents.length).toBe(1);
    expect(receivedEvents[0].action.type).toBe("GENESIS");

    // Append some custom user actions
    await session.appendEvent({ type: "VOTE", optionId: "opt-1" });
    await session.appendEvent({ type: "COMMENT", text: "Hello Zero Knowledge!" });

    // Wait for subscription delivery
    await new Promise(r => setTimeout(r, 50));

    expect(receivedEvents.length).toBe(3);
    
    // Check decrypted actions
    expect(receivedEvents[1].action).toEqual({ type: "VOTE", optionId: "opt-1" });
    expect(receivedEvents[2].action).toEqual({ type: "COMMENT", text: "Hello Zero Knowledge!" });

    // Check that signers match
    expect(receivedEvents[1].signerPublicKey).toBe(session.getSignerPublicKey());
    expect(receivedEvents[2].signerPublicKey).toBe(session.getSignerPublicKey());

    unsubscribe();
  });

  test("Access Denied throws when no credentials found and no key provided", async () => {
    await expect(getLedgerSession("non-existent-ledger")).rejects.toThrow("Access Denied");
  });
});
