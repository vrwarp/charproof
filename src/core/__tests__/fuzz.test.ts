import { describe, it, expect, beforeEach } from "vitest";
import {
  unwrapActiveAmk,
  prepareGenesisDocument,
  prepareRegistrationData,
  rotateKeys,
  preparePendingDeviceRequest,
  preparePendingDeviceApproval
} from "../deviceLogic";
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
  importSymmetricKey,
  encrypt,
  decrypt,
  generateIdentityKeyPair,
  exportPublicKey,
  generateDeviceKeyPair,
  exportDevicePublicKey,
  exportDevicePrivateKey,
  wrapAmk,
  unwrapAmk
} from "../crypto";
import type { AccountKeysDocument } from "../types";
import {
  DeterministicCryptoProvider,
  MockAccountKeyStore,
  MockLedgerEventStore,
  MockLocalDeviceStore,
  createPRNG
} from "./DeterministicMocks";

describe("Zero-Knowledge Core Fuzz & Concurrency Test Suite", () => {
  let cryptoProvider: DeterministicCryptoProvider;

  beforeEach(() => {
    cryptoProvider = new DeterministicCryptoProvider(42);
    setCryptoProvider(cryptoProvider);
  });

  describe("Deterministic Cryptographic Provider Sandboxing", () => {
    it("should generate 100% deterministic symmetric keys given the same seed sequence", async () => {
      const provider1 = new DeterministicCryptoProvider(12345);
      const provider2 = new DeterministicCryptoProvider(12345);

      const key1 = await provider1.generateSymmetricKey(256);
      const key2 = await provider2.generateSymmetricKey(256);

      const raw1 = await provider1.exportSymmetricKey(key1);
      const raw2 = await provider2.exportSymmetricKey(key2);

      expect(raw1).toEqual(raw2);
    });

    it("should encrypt and decrypt a message with complete correctness", async () => {
      const key = await generateSymmetricKey(256);
      const message = "Highly sensitive user data!";
      
      const { ciphertext, iv } = await encrypt(key, message);
      expect(ciphertext).not.toBe(message);

      const decrypted = await decrypt(key, ciphertext, iv);
      expect(decrypted).toBe(message);
    });

    it("should fail decryption when using the wrong key", async () => {
      const key1 = await generateSymmetricKey(256);
      const key2 = await generateSymmetricKey(256);
      const message = "Keep it secret";

      const { ciphertext, iv } = await encrypt(key1, message);
      
      const decryptedWithWrongKey = await decrypt(key2, ciphertext, iv);
      expect(decryptedWithWrongKey).not.toBe(message);
    });

    it("should sign and verify ECDSA actions correctly", async () => {
      const { publicKey, privateKey } = await generateIdentityKeyPair();
      const action = { type: "VOTE_CAST", payload: { pollId: "abc", slot: 1 } };

      const signature = await prepareAppendEventEnvelope(privateKey, await exportPublicKey(publicKey), action, await generateSymmetricKey(256));
      expect(signature.encryptedData).toBeDefined();
    });

    it("should wrap and unwrap symmetric keys using RSA-OAEP correctly", async () => {
      const { publicKey, privateKey } = await generateDeviceKeyPair();
      const amk = await generateSymmetricKey(256);
      const rawAmk = await cryptoProvider.exportSymmetricKey(amk);

      const wrapped = await wrapAmk(publicKey, rawAmk.buffer as ArrayBuffer);
      const unwrappedRaw = await unwrapAmk(privateKey, wrapped);

      expect(new Uint8Array(unwrappedRaw)).toEqual(new Uint8Array(rawAmk));
    });
  });

  describe("Device Lifecycle, Pairing, and Revocation Logic", () => {
    it("should execute Genesis Device setup and allow the genesis device to unwrap the active AMK", async () => {
      const deviceId = "device-genesis";
      const deviceName = "Genesis iPhone";
      
      const deviceKeyPair = await generateDeviceKeyPair();
      const devicePubB64 = await exportDevicePublicKey(deviceKeyPair.publicKey);
      const devicePrivB64 = await exportDevicePrivateKey(deviceKeyPair.privateKey);

      const prfKey = await generateSymmetricKey(256);
      const prfMethodId = "prf-method-id";

      const { doc: accountKeysDoc, rawAmk } = await prepareGenesisDocument(
        deviceId,
        deviceName,
        devicePubB64,
        "cred-id-1",
        prfKey,
        prfMethodId
      );

      expect(accountKeysDoc.activeAmkId).toBe("amk_v1");
      expect(accountKeysDoc.devices[deviceId]).toBeDefined();
      expect(accountKeysDoc.keyring["amk_v1"][deviceId]).toBeDefined();

      const unwrappedAmk = await unwrapActiveAmk(accountKeysDoc, deviceId, devicePrivB64);
      expect(new Uint8Array(unwrappedAmk)).toEqual(new Uint8Array(rawAmk));
    });

    it("should handle multi-device authorization: Device A approves Device B, giving B AMK access", async () => {
      const devAId = "device-a";
      const devKeyPairA = await generateDeviceKeyPair();
      const devPubA = await exportDevicePublicKey(devKeyPairA.publicKey);
      const devPrivA = await exportDevicePrivateKey(devKeyPairA.privateKey);
      
      const prfKey = await generateSymmetricKey(256);
      const { doc: genesisDoc, rawAmk: rawAmkHex } = await prepareGenesisDocument(
        devAId,
        "Device A",
        devPubA,
        "cred-a",
        prfKey,
        "prf-a"
      );

      const devBId = "device-b";
      const devKeyPairB = await generateDeviceKeyPair();
      const devPubB = await exportDevicePublicKey(devKeyPairB.publicKey);
      const devPrivB = await exportDevicePrivateKey(devKeyPairB.privateKey);

      const pendingRequest = await preparePendingDeviceRequest(
        devBId,
        "Device B",
        devPubB,
        genesisDoc
      );

      expect(pendingRequest.deviceId).toBe(devBId);
      expect(pendingRequest.encryptedDeviceName.wrappedKeys[devAId]).toBeDefined();

      const activeAmk = await importSymmetricKey(btoa(String.fromCharCode(...new Uint8Array(rawAmkHex))));
      const activeAmkId = genesisDoc.activeAmkId;

      const { wrappedAmk } = await preparePendingDeviceApproval(
        devAId,
        devPrivA,
        pendingRequest,
        activeAmk,
        activeAmkId
      );

      const updatedDoc = await prepareRegistrationData(
        activeAmk,
        activeAmkId,
        "Device B",
        devBId,
        devPubB,
        genesisDoc
      );

      updatedDoc.keyring[activeAmkId][devBId] = wrappedAmk;

      const unwrappedAmkForB = await unwrapActiveAmk(updatedDoc, devBId, devPrivB);
      expect(new Uint8Array(unwrappedAmkForB)).toEqual(new Uint8Array(rawAmkHex));
    });

    it("should handle Key Rotation & Device Revocation seamlessly", async () => {
      const devAId = "device-a";
      const devKeyPairA = await generateDeviceKeyPair();
      const devPubA = await exportDevicePublicKey(devKeyPairA.publicKey);
      const devPrivA = await exportDevicePrivateKey(devKeyPairA.privateKey);

      const devBId = "device-b";
      const devKeyPairB = await generateDeviceKeyPair();
      const devPubB = await exportDevicePublicKey(devKeyPairB.publicKey);
      const devPrivB = await exportDevicePrivateKey(devKeyPairB.privateKey);

      const devCId = "device-c";
      const devKeyPairC = await generateDeviceKeyPair();
      const devPubC = await exportDevicePublicKey(devKeyPairC.publicKey);
      const devPrivC = await exportDevicePrivateKey(devKeyPairC.privateKey);

      const prfKey = await generateSymmetricKey(256);
      
      const { doc: genesisDoc } = await prepareGenesisDocument(
        devAId,
        "Device A",
        devPubA,
        "cred-a",
        prfKey,
        "prf-a"
      );

      const activeAmk = await importSymmetricKey(await exportSymmetricKey(await generateSymmetricKey(256)));
      
      let docState = await prepareRegistrationData(activeAmk, "amk_v1", "Device B", devBId, devPubB, genesisDoc);
      const rawActiveAmkB = await cryptoProvider.exportSymmetricKey(activeAmk);
      docState.keyring["amk_v1"][devBId] = await wrapAmk(devKeyPairB.publicKey, rawActiveAmkB.buffer as ArrayBuffer);

      docState = await prepareRegistrationData(activeAmk, "amk_v1", "Device C", devCId, devPubC, docState);
      const rawActiveAmkC = await cryptoProvider.exportSymmetricKey(activeAmk);
      docState.keyring["amk_v1"][devCId] = await wrapAmk(devKeyPairC.publicKey, rawActiveAmkC.buffer as ArrayBuffer);

      const newAmk = await generateSymmetricKey(256);
      const newAmkId = "amk_v2";

      const rotatedDoc = await rotateKeys(
        devCId,
        docState,
        activeAmk,
        newAmk,
        newAmkId,
        prfKey
      );

      expect(rotatedDoc.devices[devCId]).toBeUndefined();
      expect(rotatedDoc.keyring[newAmkId][devAId]).toBeDefined();
      expect(rotatedDoc.keyring[newAmkId][devBId]).toBeDefined();
      expect(rotatedDoc.keyring[newAmkId][devCId]).toBeUndefined();

      const unwrappedA = await unwrapActiveAmk(rotatedDoc, devAId, devPrivA);
      const unwrappedB = await unwrapActiveAmk(rotatedDoc, devBId, devPrivB);
      expect(unwrappedA).toEqual(unwrappedB);

      const expectedNewAmkRaw = await cryptoProvider.exportSymmetricKey(newAmk);
      expect(new Uint8Array(unwrappedA)).toEqual(new Uint8Array(expectedNewAmkRaw));

      await expect(unwrapActiveAmk(rotatedDoc, devCId, devPrivC)).rejects.toThrow();
    });
  });

  describe("Session Logic, Digital Signatures, and Recoverability", () => {
    it("should prepare, decrypt, and validate sequential ledger events correctly", async () => {
      const symmetricKey = await generateSymmetricKey(256);
      const { publicKey, privateKey } = await generateIdentityKeyPair();
      const pubB64 = await exportPublicKey(publicKey);

      const action1 = { type: "ADD_POLL", payload: { title: "Lunch Meet" } };
      const action2 = { type: "CAST_VOTE", payload: { slots: [1, 2, 3] } };

      const envelope1 = await prepareAppendEventEnvelope(privateKey, pubB64, action1, symmetricKey);
      const envelope2 = await prepareAppendEventEnvelope(privateKey, pubB64, action2, symmetricKey);

      const event1 = await decryptAndValidateEvent(envelope1.encryptedData, envelope1.iv, symmetricKey);
      expect(event1).not.toBeNull();
      expect(event1!.signerPublicKey).toBe(pubB64);
      expect(event1!.action).toEqual(action1);

      const event2 = await decryptAndValidateEvent(envelope2.encryptedData, envelope2.iv, symmetricKey);
      expect(event2).not.toBeNull();
      expect(event2!.signerPublicKey).toBe(pubB64);
      expect(event2!.action).toEqual(action2);
    });

    it("should process ledger snapshots and filter out invalid/tampered events", async () => {
      const symmetricKey = await generateSymmetricKey(256);
      const { publicKey, privateKey } = await generateIdentityKeyPair();
      const pubB64 = await exportPublicKey(publicKey);

      const validEnv = await prepareAppendEventEnvelope(privateKey, pubB64, { type: "OK" }, symmetricKey);
      const tamperedEnv = await prepareAppendEventEnvelope(privateKey, pubB64, { type: "BAD" }, symmetricKey);
      tamperedEnv.encryptedData = btoa("Tampered Encrypted Data Payload");

      const snapshot = [
        { id: "1", encryptedData: validEnv.encryptedData, iv: validEnv.iv },
        { id: "2", encryptedData: tamperedEnv.encryptedData, iv: tamperedEnv.iv }
      ];

      const processed = await processLedgerEventSnapshot(snapshot, symmetricKey);
      expect(processed.length).toBe(1);
      expect(processed[0].action).toEqual({ type: "OK" });
    });

    it("should successfully recover ledger credentials using the ownership token", async () => {
      const material = await prepareGenesisCredentials();
      const genesisEvent = await prepareAppendEventEnvelope(
        material.signingPrivateKey,
        material.creds.signingPublicKey,
        { type: "GENESIS" },
        material.symmetricKey,
        material.ownerRecovery
      );

      const recoveredCreds = await attemptRecoveryWithToken(
        material.ownershipToken,
        material.creds.symmetricKey,
        genesisEvent
      );

      expect(recoveredCreds).not.toBeNull();
      expect(recoveredCreds!.symmetricKey).toBe(material.creds.symmetricKey);
      expect(recoveredCreds!.signingPrivateKey).toBe(material.creds.signingPrivateKey);
      expect(recoveredCreds!.signingPublicKey).toBe(material.creds.signingPublicKey);
    });
  });

  describe("Transaction Concurrency & Write Collision Resolution", () => {
    it("should resolve write collisions successfully through transaction retries", async () => {
      const store = new MockAccountKeyStore();
      
      const initialDoc = {
        activeAmkId: "amk_v1",
        devices: {},
        recoveryMethods: {},
        keyring: {}
      } as AccountKeysDocument;
      
      await store.setAccountKeys(initialDoc);

      store.transactionCollisionsToSimulate = 3;

      let updaterRan = 0;
      await store.transactAccountKeys(async (current) => {
        updaterRan++;
        return {
          ...current,
          activeAmkId: `amk_success_retry_${updaterRan}`
        };
      });

      expect(store.transactionAttempts).toBe(4);
      expect(updaterRan).toBe(4);
      expect(store.accountKeys!.activeAmkId).toBe("amk_success_retry_4");
    });
  });

  describe("Deterministic Combinatorial Fuzzing (Extreme Paranoid Sandbox)", () => {
    const seeds = Array.from({ length: 30 }, (_, i) => i * 1111);

    seeds.forEach((seed) => {
      it(`Fuzz Test permutation with seed: ${seed}`, async () => {
        const fuzzPrng = createPRNG(seed);
        const fuzzCrypto = new DeterministicCryptoProvider(seed);
        setCryptoProvider(fuzzCrypto);

        const store = new MockAccountKeyStore();
        const eventStore = new MockLedgerEventStore();

        const deviceCount = Math.floor(fuzzPrng() * 6) + 3;
        const devices: Array<{
          id: string;
          name: string;
          publicKey: any;
          privateKey: any;
          pubB64: string;
          privB64: string;
          localStore: MockLocalDeviceStore;
          isAuthorized: boolean;
        }> = [];

        for (let i = 0; i < deviceCount; i++) {
          const id = `fuzz-dev-${i}`;
          const name = `Fuzz Device ${i}`;
          const pair = await generateDeviceKeyPair();
          const pubB64 = await exportDevicePublicKey(pair.publicKey);
          const privB64 = await exportDevicePrivateKey(pair.privateKey);
          
          const localStore = new MockLocalDeviceStore(id, name);
          await localStore.saveDeviceKeys({ privateKey: privB64, publicKey: pubB64 });

          devices.push({
            id,
            name,
            publicKey: pair.publicKey,
            privateKey: pair.privateKey,
            pubB64,
            privB64,
            localStore,
            isAuthorized: false
          });
        }

        const genDev = devices[0];
        const prfKey = await generateSymmetricKey(256);
        const { doc: genesisDoc, rawAmk: rawGenesisAmk } = await prepareGenesisDocument(
          genDev.id,
          genDev.name,
          genDev.pubB64,
          "prf-cred-genesis",
          prfKey,
          "prf-method-genesis"
        );
        await store.setAccountKeys(genesisDoc);
        genDev.isAuthorized = true;

        const totalOps = Math.floor(fuzzPrng() * 15) + 10;
        let currentAmk = await importSymmetricKey(btoa(String.fromCharCode(...new Uint8Array(rawGenesisAmk))));
        const ledgerSymmetricKey = await generateSymmetricKey(256);

        for (let opIdx = 0; opIdx < totalOps; opIdx++) {
          const activeDevices = devices.filter(d => d.isAuthorized);
          const inactiveDevices = devices.filter(d => !d.isAuthorized);

          const choice = fuzzPrng();

          if (choice < 0.4 && inactiveDevices.length > 0) {
            const newDev = inactiveDevices[Math.floor(fuzzPrng() * inactiveDevices.length)];
            const sponsor = activeDevices[Math.floor(fuzzPrng() * activeDevices.length)];

            const currentDoc = await store.getAccountKeys();
            const pendingReq = await preparePendingDeviceRequest(
              newDev.id,
              newDev.name,
              newDev.pubB64,
              currentDoc!
            );
            await store.setPendingDevice(newDev.id, pendingReq);

            const activeAmkVal = currentAmk;
            const activeAmkId = currentDoc!.activeAmkId;

            const { wrappedAmk } = await preparePendingDeviceApproval(
              sponsor.id,
              sponsor.privB64,
              pendingReq,
              activeAmkVal,
              activeAmkId
            );

            const updated = await prepareRegistrationData(
              activeAmkVal,
              activeAmkId,
              newDev.name,
              newDev.id,
              newDev.pubB64,
              currentDoc!
            );
            updated.keyring[activeAmkId][newDev.id] = wrappedAmk;
            
            await store.setAccountKeys(updated);
            newDev.isAuthorized = true;

          } else if (choice < 0.7 && activeDevices.length > 2) {
            const toRevoke = activeDevices[Math.floor(fuzzPrng() * (activeDevices.length - 1)) + 1];

            const currentDoc = await store.getAccountKeys();
            const rotatedAmkKey = await generateSymmetricKey(256);
            const rotatedAmkId = `amk_rotated_${opIdx}`;

            const updatedDoc = await rotateKeys(
              toRevoke.id,
              currentDoc!,
              currentAmk,
              rotatedAmkKey,
              rotatedAmkId,
              prfKey
            );

            await store.setAccountKeys(updatedDoc);
            currentAmk = rotatedAmkKey;
            toRevoke.isAuthorized = false;

          } else {
            const sponsor = activeDevices[Math.floor(fuzzPrng() * activeDevices.length)];
            const identityKeyPair = await generateIdentityKeyPair();
            const sponsorPub = await exportPublicKey(identityKeyPair.publicKey);
            
            const eventEnvelope = await prepareAppendEventEnvelope(
              identityKeyPair.privateKey,
              sponsorPub,
              { op: opIdx, data: `Fuzz Action ${opIdx}` },
              ledgerSymmetricKey
            );

            await eventStore.appendEvent("fuzz-ledger", `ev-${opIdx}`, eventEnvelope);
          }

          const currentDoc = await store.getAccountKeys();
          expect(currentDoc).not.toBeNull();

          const docDevices = Object.keys(currentDoc!.devices);
          for (const dev of devices) {
            if (dev.isAuthorized) {
              expect(docDevices).toContain(dev.id);
              const unwrapped = await unwrapActiveAmk(currentDoc!, dev.id, dev.privB64);
              const expectedRaw = await fuzzCrypto.exportSymmetricKey(currentAmk);
              expect(new Uint8Array(unwrapped)).toEqual(new Uint8Array(expectedRaw));
            } else {
              await expect(unwrapActiveAmk(currentDoc!, dev.id, dev.privB64)).rejects.toThrow();
            }
          }

          const allRawEvents = eventStore.events["fuzz-ledger"] || [];
          const processedEvents = await processLedgerEventSnapshot(allRawEvents, ledgerSymmetricKey);
          expect(processedEvents.length).toBe(allRawEvents.length);
        }
      });
    });
  });
});
