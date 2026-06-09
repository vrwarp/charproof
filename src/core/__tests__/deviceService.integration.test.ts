import { describe, test, expect, beforeEach } from "vitest";
import { setCryptoProvider } from "../../core/crypto";
import {
  setDeviceServiceProviders,
  setPrfProviders,
  getActiveAmk,
  getAmkById,
  clearAmkSessionCache,
  clearPrfSessionCache,
  getRecoveryStatus,
  registerCurrentDevice,
  enablePrfRecovery,
  revokeDevice,
  saveToKeystore,
  loadFromKeystore,
  verifyAmk,
  requestDeviceAuthorization,
  approveDeviceAuthorization,
  getVerificationCodeForPublicKey,
  getLocalVerificationCode,
  setupPhraseRecovery,
  recoverAmkWithPhrase,
  setRecoveryProviders,
  setDeviceName,
  getDeviceName
} from "../../index";
import {
  getCrypto,
  encrypt,
  encryptPayload,
  wrapAmk,
  exportDevicePublicKey
} from "../../core/crypto";
import * as bip39 from "bip39";
import {
  DeterministicCryptoProvider,
  MockAccountKeyStore,
  MockLocalDeviceStore,
  MockAuthProvider,
  MockPrfProvider
} from "./DeterministicMocks";
import type { AccountKeysDocument, PendingDevice } from "../../core/types";

describe("deviceService Integration Tests", () => {
  let cryptoProvider: DeterministicCryptoProvider;
  let accountKeyStore: MockAccountKeyStore;
  let localDeviceStore: MockLocalDeviceStore;
  let authProvider: MockAuthProvider;
  let prfProvider: MockPrfProvider;

  function resetAllCaches() {
    clearAmkSessionCache();
    clearPrfSessionCache();
  }

  beforeEach(() => {
    cryptoProvider = new DeterministicCryptoProvider(42);
    accountKeyStore = new MockAccountKeyStore();
    localDeviceStore = new MockLocalDeviceStore("device-a", "Alice's Mac");
    authProvider = new MockAuthProvider();
    prfProvider = new MockPrfProvider();

    setCryptoProvider(cryptoProvider);
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore, authProvider });
    setPrfProviders({ localDeviceStore, authProvider, prfProvider });
    setRecoveryProviders({ accountKeyStore, authProvider });
    resetAllCaches();

    // Default setup: signed in user
    authProvider.currentUser = {
      uid: "user-123",
      isAnonymous: false,
      email: "user@example.com",
      displayName: "Alice"
    };
  });

  test("Genesis flow - getActiveAmk() on fresh account creates keys and stores them", async () => {
    // Fresh account keys are null, local device has no keys
    const result = await getActiveAmk();
    expect(result.amk).toBeDefined();
    expect(result.amkId).toBeDefined();

    // Verify stored account keys doc
    const storedDoc = await accountKeyStore.getAccountKeys();
    expect(storedDoc).not.toBeNull();
    expect(storedDoc!.activeAmkId).toBe(result.amkId);
    expect(storedDoc!.devices[localDeviceStore.getDeviceId()]).toBeDefined();

    // Verify local device keys
    const localKeys = await localDeviceStore.loadDeviceKeys();
    expect(localKeys).not.toBeNull();
  });

  test("AMK caching and clearAmkSessionCache()", async () => {
    const result1 = await getActiveAmk();

    // Modify stored activeAmkId to see if cache gets hit
    const storedDoc = await accountKeyStore.getAccountKeys();
    const oldId = storedDoc!.activeAmkId;
    
    // Wrap for same device under a mock modified id
    storedDoc!.keyring["modified_id"] = {
      "device-a": storedDoc!.keyring[oldId]["device-a"]
    };
    storedDoc!.activeAmkId = "modified_id";
    await accountKeyStore.setAccountKeys(storedDoc!);

    // Should return cached
    const result2 = await getActiveAmk();
    expect(result2.amkId).toBe(oldId);

    // Clear cache, should get new active id (from store)
    resetAllCaches();
    const result3 = await getActiveAmk();
    expect(result3.amkId).toBe("modified_id");
  });

  test("Second device registration flow (pending -> approved)", async () => {
    // 1. Setup genesis on Device A
    const devA_Id = localDeviceStore.getDeviceId();
    const devA_Result = await getActiveAmk();

    // 2. Simulate Device B
    const devB_Store = new MockLocalDeviceStore("device-b", "Alice's iPhone");
    const devB_Id = devB_Store.getDeviceId();

    // Switch to Device B environment
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider });
    resetAllCaches();

    // Request authorization on Device B
    await requestDeviceAuthorization();

    // Check pending device exists
    const pending = await accountKeyStore.getPendingDevice(devB_Id);
    expect(pending).not.toBeNull();
    expect(pending!.deviceId).toBe(devB_Id);
    expect(pending!.status).toBe("pending");

    // 3. Switch back to Device A to approve
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore, authProvider });
    resetAllCaches();

    await approveDeviceAuthorization(pending!);

    // 4. Switch back to Device B, active AMK should now be accessible
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider });
    resetAllCaches();

    const devB_Result = await getActiveAmk();
    expect(devB_Result.amkId).toBe(devA_Result.amkId);
  });

  test("Revocation and AMK rotation in a 3-device setup", async () => {
    // 1. Setup Device A (Genesis)
    const devA_Id = localDeviceStore.getDeviceId();
    const devA_Result = await getActiveAmk();

    // Disable PRF recovery for this test to focus on device-key-based revocation isolation
    const doc = await accountKeyStore.getAccountKeys();
    doc!.recoveryMethods = {};
    doc!.keyring["amk_v1"] = {
      "device-a": doc!.keyring["amk_v1"]["device-a"]
    };
    await accountKeyStore.setAccountKeys(doc!);

    // Delete the local PRF recovery master key from Device A so it does not opportunistically re-enable/re-seal it
    await localDeviceStore.saveMasterKey("user-123", null as any);

    // 2. Setup Device B
    const devB_Store = new MockLocalDeviceStore("device-b", "Alice's Phone");
    const devB_Id = devB_Store.getDeviceId();
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider });
    resetAllCaches();
    await requestDeviceAuthorization();
    const pendingB = await accountKeyStore.getPendingDevice(devB_Id);

    setDeviceServiceProviders({ accountKeyStore, localDeviceStore, authProvider });
    resetAllCaches();
    await approveDeviceAuthorization(pendingB!);

    // 3. Setup Device C
    const devC_Store = new MockLocalDeviceStore("device-c", "Alice's Tablet");
    const devC_Id = devC_Store.getDeviceId();
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devC_Store, authProvider });
    resetAllCaches();
    await requestDeviceAuthorization();
    const pendingC = await accountKeyStore.getPendingDevice(devC_Id);

    setDeviceServiceProviders({ accountKeyStore, localDeviceStore, authProvider });
    resetAllCaches();
    await approveDeviceAuthorization(pendingC!);

    // 4. Device A revokes Device C
    const activeBefore = await getActiveAmk();
    await revokeDevice(devC_Id);

    // After rotation, active AMK should be different
    const activeAfter = await getActiveAmk();
    expect(activeAfter.amkId).not.toBe(activeBefore.amkId);

    // Device B should still be able to get active AMK
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider });
    resetAllCaches();
    const devB_Active = await getActiveAmk();
    expect(devB_Active.amkId).toBe(activeAfter.amkId);

    // Device C should FAIL to get active AMK because it was revoked
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devC_Store, authProvider });
    resetAllCaches();
    await expect(getActiveAmk()).rejects.toThrow("UNRECOGNIZED_DEVICE");
  });

  test("PRF silent recovery flow", async () => {
    // 1. Genesis on Device A
    await getActiveAmk();

    // Remove PRF recovery method to simulate unregistered/un-enabled PRF recovery initially
    const doc = await accountKeyStore.getAccountKeys();
    doc!.recoveryMethods = {};
    doc!.keyring["amk_v1"] = {
      "device-a": doc!.keyring["amk_v1"]["device-a"]
    };
    await accountKeyStore.setAccountKeys(doc!);
    await localDeviceStore.saveMasterKey("user-123", null as any);

    // 2. Simulating new Device B that has never been registered
    const devB_Store = new MockLocalDeviceStore("device-b", "New PRF Device");
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider });
    resetAllCaches();

    // Active AMK fails normally because Device B has no keys and PRF is not registered/enabled
    await expect(getActiveAmk()).rejects.toThrow("UNRECOGNIZED_DEVICE");

    // Switch back to Device A to enable PRF recovery
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore, authProvider });
    resetAllCaches();
    await enablePrfRecovery();

    // Switch back to Device B. Since we share MockAuthProvider and MockPrfProvider,
    // getActiveAmk() will trigger tryRecoverAmkWithPrf() and succeed silently!
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider });
    resetAllCaches();

    const devB_Result = await getActiveAmk();
    expect(devB_Result.amkId).toBeDefined();

    // Device B should also be registered in the keyring now
    const storedDoc = await accountKeyStore.getAccountKeys();
    expect(storedDoc!.devices[devB_Store.getDeviceId()]).toBeDefined();
  });

  test("Auth guard - throws when signed out", async () => {
    authProvider.currentUser = null;
    await expect(getActiveAmk()).rejects.toThrow("Must be signed in to access AMK.");
  });

  test("Keystore round-trip with rotated AMKs", async () => {
    await getActiveAmk();

    const credentials = {
      symmetricKey: "symmetric-123",
      signingPrivateKey: "private-123",
      signingPublicKey: "public-123"
    };

    // Save with AMK v1
    await saveToKeystore("ledger-xyz", credentials);

    // Retrieve
    const retrieved = await loadFromKeystore("ledger-xyz");
    expect(retrieved).toEqual(credentials);

    // Simulate Device B requesting and being approved so we can rotate safely
    const devB_Store = new MockLocalDeviceStore("device-b", "B");
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider });
    resetAllCaches();
    await requestDeviceAuthorization();
    const pendingB = await accountKeyStore.getPendingDevice("device-b");

    // Switch to Device A to approve B and then revoke a non-existent device to force rotation
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore, authProvider });
    resetAllCaches();
    await approveDeviceAuthorization(pendingB!);
    await revokeDevice("non-existent-device");

    // Retrieve again - should still work by loading historical AMK v1
    const retrievedAfterRotation = await loadFromKeystore("ledger-xyz");
    expect(retrievedAfterRotation).toEqual(credentials);
  });

  test("getRecoveryStatus() returns status", async () => {
    // Fresh setup - no recovery sealed
    const status1 = await getRecoveryStatus();
    expect(status1.isSealed).toBe(false);

    // Setup active AMK
    await getActiveAmk();

    // Seal PRF recovery
    await enablePrfRecovery();

    const status2 = await getRecoveryStatus();
    expect(status2.isSealed).toBe(true);
    expect(status2.methods.length).toBe(1);
    expect(status2.isCurrentPrfSealed).toBe(true);
  });

  test("verifyAmk() returns boolean status", async () => {
    // First, setup genesis on Device A so the account keys doc exists
    await getActiveAmk();

    // Remove PRF recovery method to simulate unregistered/un-enabled PRF recovery initially
    const doc = await accountKeyStore.getAccountKeys();
    doc!.recoveryMethods = {};
    doc!.keyring["amk_v1"] = {
      "device-a": doc!.keyring["amk_v1"]["device-a"]
    };
    await accountKeyStore.setAccountKeys(doc!);
    await localDeviceStore.saveMasterKey("user-123", null as any);

    // Now, switch to an unrecognized Device B (which has no keys registered in keyring)
    const devB_Store = new MockLocalDeviceStore("device-b", "Alice's Phone");
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider });
    resetAllCaches();

    // Now verifyAmk() should return false because it's unrecognized
    const val1 = await verifyAmk();
    expect(val1).toBe(false);

    // Switch back to Device A (recognized)
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore, authProvider });
    resetAllCaches();
    const val2 = await verifyAmk();
    expect(val2).toBe(true);
  });

  test("Concurrent getActiveAmk() deduplicates store requests", async () => {
    // Trigger multiple active AMK gets in parallel
    const promises = Array.from({ length: 5 }, () => getActiveAmk());
    const results = await Promise.all(promises);

    expect(results[0].amkId).toBeDefined();
    for (const res of results) {
      expect(res.amkId).toBe(results[0].amkId);
    }
  });

  test("approveDeviceAuthorization enforces a matching verification code", async () => {
    // Genesis on Device A
    await getActiveAmk();

    // Device B requests authorization
    const devB_Store = new MockLocalDeviceStore("device-b", "Alice's iPhone");
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore: devB_Store, authProvider });
    resetAllCaches();
    await requestDeviceAuthorization();
    const pending = await accountKeyStore.getPendingDevice("device-b");
    expect(pending).not.toBeNull();

    // Back to Device A to approve
    setDeviceServiceProviders({ accountKeyStore, localDeviceStore, authProvider });
    resetAllCaches();

    // Wrong code is rejected and does NOT authorize the device.
    await expect(
      approveDeviceAuthorization(pending!, { expectedVerificationCode: "000000" })
    ).rejects.toThrow("VERIFICATION_CODE_MISMATCH");

    let doc = await accountKeyStore.getAccountKeys();
    expect(doc!.devices["device-b"]).toBeUndefined();

    // Correct code (derived from the pending device's public key) succeeds.
    const correctCode = await getVerificationCodeForPublicKey(pending!.publicKey);
    await approveDeviceAuthorization(pending!, { expectedVerificationCode: correctCode });

    doc = await accountKeyStore.getAccountKeys();
    expect(doc!.devices["device-b"]).toBeDefined();
  });

  test("getLocalVerificationCode matches the code computed from the device's public key", async () => {
    await getActiveAmk();
    const localKeys = await localDeviceStore.loadDeviceKeys();
    expect(localKeys).not.toBeNull();

    const fromLocal = await getLocalVerificationCode();
    const fromPub = await getVerificationCodeForPublicKey(localKeys!.publicKey);
    expect(fromLocal).toBe(fromPub);
    expect(fromLocal).toMatch(/^\d{6}$/);
  });

  test("Genesis lost-race: recovers from the winning document without clobbering keys", async () => {
    // First, perform a normal genesis on Device A so a valid document + device
    // keys exist (the "winner").
    const winning = await getActiveAmk();
    const winningKeys = await localDeviceStore.loadDeviceKeys();
    expect(winningKeys).not.toBeNull();

    // A store that reports "no document" on the next getAccountKeys() (simulating
    // the read that precedes genesis) but still rejects the create as a loser.
    let raceArmed = true;
    const raceyStore = Object.create(accountKeyStore) as MockAccountKeyStore;
    raceyStore.getAccountKeys = async () => {
      if (raceArmed) {
        raceArmed = false;
        return null; // pretend the account doesn't exist yet → drives genesis path
      }
      return accountKeyStore.getAccountKeys();
    };
    raceyStore.createAccountKeys = async () => false; // we always lose the race

    setDeviceServiceProviders({ accountKeyStore: raceyStore, localDeviceStore, authProvider });
    resetAllCaches();

    const recovered = await getActiveAmk();
    expect(recovered.amkId).toBe(winning.amkId);

    // The winner's device keys must be intact (not clobbered by the loser).
    const keysAfter = await localDeviceStore.loadDeviceKeys();
    expect(keysAfter).toEqual(winningKeys);
  });

  test("Genesis lost-race with fresh keys fails cleanly without clobbering IndexedDB", async () => {
    // Winner: normal genesis on Device A; its keys live in `localDeviceStore`.
    await getActiveAmk();

    // Loser: a second tab on the same device id but a DIFFERENT, empty local
    // store, so it generates fresh keys that do NOT match the winning document.
    const loserStore = new MockLocalDeviceStore("device-a", "Alice's Mac (tab 2)");

    let raceArmed = true;
    const raceyStore = Object.create(accountKeyStore) as MockAccountKeyStore;
    raceyStore.getAccountKeys = async () => {
      if (raceArmed) {
        raceArmed = false;
        return null; // drive the genesis path
      }
      return accountKeyStore.getAccountKeys(); // winning doc on the retry read
    };
    raceyStore.createAccountKeys = async () => false; // always lose the race

    setDeviceServiceProviders({ accountKeyStore: raceyStore, localDeviceStore: loserStore, authProvider });
    setPrfProviders({ localDeviceStore: loserStore, authProvider, prfProvider });
    resetAllCaches();

    await expect(getActiveAmk()).rejects.toThrow("UNRECOGNIZED_DEVICE");

    // The loser must NOT have persisted its freshly-generated keys — doing so
    // would clobber the winning device's keys in shared IndexedDB.
    expect(await loserStore.loadDeviceKeys()).toBeNull();
  });

  test("Phrase recovery round-trips the AMK (random per-record salt path)", async () => {
    const { amk } = await getActiveAmk();
    const expectedRaw = await getCrypto().exportSymmetricKey(amk);

    const mnemonic = await setupPhraseRecovery();
    expect(mnemonic.split(" ").length).toBe(24);

    // The stored entry must carry a per-record salt (not a hardcoded constant).
    const doc = await accountKeyStore.getAccountKeys();
    const entry = JSON.parse((doc!.recoveryMethods["__recovery_phrase"] as any).encryptedPrivateKey);
    expect(typeof entry.kdfSalt).toBe("string");
    expect(entry.kdfSalt.length).toBeGreaterThan(0);

    const recovered = await recoverAmkWithPhrase(mnemonic);
    const recoveredRaw = await getCrypto().exportSymmetricKey(recovered.amk);
    expect(new Uint8Array(recoveredRaw)).toEqual(new Uint8Array(expectedRaw));
  });

  test("Phrase recovery falls back to legacy derivation for pre-salt entries", async () => {
    const { amk, amkId } = await getActiveAmk();
    const expectedRaw = await getCrypto().exportSymmetricKey(amk);

    // Reconstruct a LEGACY phrase-recovery entry exactly as the pre-change code
    // wrote it: constant salt, 100k iterations, and NO kdfSalt field.
    const mnemonic = bip39.generateMnemonic(256);
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const password = new Uint8Array(seed.slice(0, 32)) as any;
    const legacySalt = new TextEncoder().encode("LetUsMeet-Recovery-Salt-v1") as any;
    const protector = (await getCrypto().deriveKeyFromPassword(password, legacySalt, 100000)) as any;

    const rsaPair = await getCrypto().generateDeviceKeyPair();
    const privRaw = await getCrypto().exportDevicePrivateKey(rsaPair.privateKey);
    const privB64 = btoa(String.fromCharCode(...new Uint8Array(privRaw)));
    const { ciphertext, iv } = await encrypt(protector, privB64);

    const rawAmk = await getCrypto().exportSymmetricKey(amk);
    const wrappedAmk = await wrapAmk(rsaPair.publicKey, rawAmk.buffer as ArrayBuffer);
    const pubB64 = await exportDevicePublicKey(rsaPair.publicKey);

    const doc = await accountKeyStore.getAccountKeys() as AccountKeysDocument;
    doc.recoveryMethods["__recovery_phrase"] = {
      type: "phrase",
      encryptedLabel: await encryptPayload(amk, "Primary Recovery Phrase"),
      publicKey: pubB64,
      createdAt: Date.now()
    };
    // Legacy format: ciphertext + iv only, no kdfSalt/kdfIterations.
    (doc.recoveryMethods["__recovery_phrase"] as any).encryptedPrivateKey = JSON.stringify({ ciphertext, iv });
    doc.keyring[amkId]["__recovery_phrase"] = wrappedAmk;
    await accountKeyStore.setAccountKeys(doc);

    const recovered = await recoverAmkWithPhrase(mnemonic);
    const recoveredRaw = await getCrypto().exportSymmetricKey(recovered.amk);
    expect(new Uint8Array(recoveredRaw)).toEqual(new Uint8Array(expectedRaw));
  });
});
