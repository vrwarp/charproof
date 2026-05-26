import { describe, it, expect } from "vitest";
import { createMachine, assign } from "xstate";
import { createModel } from "@xstate/test";
import {
  unwrapActiveAmk,
  unwrapAmkById,
  tryRecoverAmkWithPrfKey,
  prepareGenesisDocument,
  prepareRegistrationData,
  rotateKeys,
  preparePendingDeviceRequest,
  preparePendingDeviceApproval
} from "../deviceLogic";
import {
  setCryptoProvider,
  generateSymmetricKey,
  importSymmetricKey,
  generateDeviceKeyPair,
  exportDevicePublicKey,
  exportDevicePrivateKey,
  importDevicePublicKey,
  wrapAmk,
  encryptPayload,
  generateIdentityKeyPair,
  exportPublicKey
} from "../crypto";
import {
  prepareAppendEventEnvelope,
  decryptAndValidateEvent,
  processLedgerEventSnapshot
} from "../sessionLogic";
import {
  DeterministicCryptoProvider,
  MockAccountKeyStore
} from "./DeterministicMocks";
import { uint8ToBase64 } from "../base64";
import { PlaintextBytes } from "../interfaces";

// ==========================================
// MODEL 1: Device Lifecycle Machine
// ==========================================

class DeviceSystemMock {
  public store = new MockAccountKeyStore();
  public cryptoProvider: DeterministicCryptoProvider;
  public devices: Record<string, {
    id: string;
    name: string;
    publicKey: any;
    privateKey: any;
    pubB64: string;
    privB64: string;
  }> = {};
  
  public prfKey!: any;
  public prfMethodId = "device-genesis-prf";
  public genesisId = "genesis-device";
  
  public phrasePubB64!: string;
  public phrasePrivB64!: string;

  public currentAmk!: any;
  public activeAmkId!: string;

  constructor() {
    this.cryptoProvider = new DeterministicCryptoProvider(42);
    setCryptoProvider(this.cryptoProvider);
  }

  async setupGenesis() {
    const pair = await generateDeviceKeyPair();
    const pubB64 = await exportDevicePublicKey(pair.publicKey);
    const privB64 = await exportDevicePrivateKey(pair.privateKey);
    
    this.devices[this.genesisId] = {
      id: this.genesisId,
      name: "Genesis Device",
      publicKey: pair.publicKey,
      privateKey: pair.privateKey,
      pubB64,
      privB64
    };

    this.prfKey = await generateSymmetricKey(256);
    const { doc: genesisDoc, rawAmk } = await prepareGenesisDocument(
      this.genesisId,
      "Genesis Device",
      pubB64,
      "prf-cred-fc",
      this.prfKey,
      this.prfMethodId
    );
    await this.store.setAccountKeys(genesisDoc);

    this.currentAmk = await importSymmetricKey(btoa(String.fromCharCode(...new Uint8Array(rawAmk))));
    this.activeAmkId = "amk_v1";
  }

  async executeRequestJoin(targetId: string, targetName: string) {
    const pair = await generateDeviceKeyPair();
    const pubB64 = await exportDevicePublicKey(pair.publicKey);
    const privB64 = await exportDevicePrivateKey(pair.privateKey);

    this.devices[targetId] = {
      id: targetId,
      name: targetName,
      publicKey: pair.publicKey,
      privateKey: pair.privateKey,
      pubB64,
      privB64
    };

    const currentDoc = await this.store.getAccountKeys();
    const pendingReq = await preparePendingDeviceRequest(
      targetId,
      targetName,
      pubB64,
      currentDoc!
    );
    await this.store.setPendingDevice(targetId, pendingReq);
  }

  async executeApprove(sponsorId: string, targetId: string) {
    const currentDoc = await this.store.getAccountKeys();
    const pendingReq = await this.store.getPendingDevice(targetId);
    
    const sponsorDev = this.devices[sponsorId];
    const targetDev = this.devices[targetId];

    const { wrappedAmk } = await preparePendingDeviceApproval(
      sponsorId,
      sponsorDev.privB64,
      pendingReq!,
      this.currentAmk,
      this.activeAmkId
    );

    const updated = await prepareRegistrationData(
      this.currentAmk,
      this.activeAmkId,
      targetDev.name,
      targetId,
      targetDev.pubB64,
      currentDoc!
    );
    updated.keyring[this.activeAmkId][targetId] = wrappedAmk;

    await this.store.setAccountKeys(updated);
  }

  async executeReject(targetId: string) {
    const pending = await this.store.getPendingDevice(targetId);
    if (pending) {
      pending.status = "rejected";
      await this.store.setPendingDevice(targetId, pending);
    }
  }

  async executeAddRecovery() {
    const currentDoc = await this.store.getAccountKeys();
    const methodId = "phrase-recovery";
    const pair = await generateDeviceKeyPair();
    const pubB64 = await exportDevicePublicKey(pair.publicKey);
    const privB64 = await exportDevicePrivateKey(pair.privateKey);

    this.phrasePubB64 = pubB64;
    this.phrasePrivB64 = privB64;

    const encryptedLabel = await encryptPayload(this.currentAmk, "Phrase method");

    currentDoc!.recoveryMethods[methodId] = {
      type: "phrase",
      encryptedLabel,
      publicKey: pubB64,
      createdAt: Date.now()
    };

    const rawAmk = await this.cryptoProvider.exportSymmetricKey(this.currentAmk);
    const recoveryPubKey = await importDevicePublicKey(pubB64);
    const wrapped = await wrapAmk(recoveryPubKey, rawAmk.buffer as ArrayBuffer);
    
    currentDoc!.keyring[this.activeAmkId][methodId] = wrapped;
    await this.store.setAccountKeys(currentDoc!);
  }

  async executeRevoke(revokerId: string, targetId: string) {
    const currentDoc = await this.store.getAccountKeys();
    const rotatedAmkKey = await generateSymmetricKey(256);
    const rotatedAmkId = "amk_rotated_xstate";

    const updatedDoc = await rotateKeys(
      targetId,
      currentDoc!,
      this.currentAmk,
      rotatedAmkKey,
      rotatedAmkId,
      this.prfKey
    );

    await this.store.setAccountKeys(updatedDoc);
    this.currentAmk = rotatedAmkKey;
    this.activeAmkId = rotatedAmkId;
  }
}

// XState definition: Unregistered (idle) -> Pending -> Authorized -> Revoked
const deviceLifecycleMachine = createMachine({
  id: "deviceLifecycle",
  initial: "Unregistered",
  states: {
    Unregistered: {
      on: { REQUEST_JOIN: "Pending" },
      meta: {
        test: async (system: DeviceSystemMock) => {
          const doc = await system.store.getAccountKeys();
          if (doc) {
            expect(doc.devices["device_B"]).toBeUndefined();
          }
          const pendingDoc = await system.store.getPendingDevice("device_B");
          if (pendingDoc) {
            expect(pendingDoc.status).toBe("rejected");
          }
        }
      }
    },
    Pending: {
      on: { 
        APPROVE: "Authorized",
        REJECT: "Unregistered" 
      },
      meta: {
        test: async (system: DeviceSystemMock) => {
          const pendingDoc = await system.store.getPendingDevice("device_B");
          expect(pendingDoc).not.toBeNull();
          expect(pendingDoc!.status).toBe("pending");
        }
      }
    },
    Authorized: {
      on: {
        ADD_RECOVERY: "AuthorizedWithRecovery",
        REVOKE: "Revoked"
      },
      meta: {
        test: async (system: DeviceSystemMock) => {
          const doc = await system.store.getAccountKeys();
          expect(doc).not.toBeNull();
          expect(doc!.devices["device_B"]).toBeDefined();
          
          const devB = system.devices["device_B"];
          const unwrapped = await unwrapActiveAmk(doc!, "device_B", devB.privB64);
          const expectedRaw = await system.cryptoProvider.exportSymmetricKey(system.currentAmk);
          expect(new Uint8Array(unwrapped)).toEqual(new Uint8Array(expectedRaw));
        }
      }
    },
    AuthorizedWithRecovery: {
      on: {
        REVOKE: "RevokedWithRecovery"
      },
      meta: {
        test: async (system: DeviceSystemMock) => {
          const doc = await system.store.getAccountKeys();
          expect(doc).not.toBeNull();
          expect(doc!.devices["device_B"]).toBeDefined();

          const expectedRaw = await system.cryptoProvider.exportSymmetricKey(system.currentAmk);
          
          // Verify both PRF and phrase recovery unwraps work
          const prfRec = await tryRecoverAmkWithPrfKey(doc!, system.prfKey, system.prfMethodId);
          expect(prfRec).not.toBeNull();
          expect(new Uint8Array(prfRec!.amkRaw)).toEqual(new Uint8Array(expectedRaw));

          const unwrappedPhrase = await unwrapAmkById(doc!, "phrase-recovery", system.phrasePrivB64, system.activeAmkId);
          expect(new Uint8Array(unwrappedPhrase)).toEqual(new Uint8Array(expectedRaw));
        }
      }
    },
    Revoked: {
      type: "final",
      meta: {
        test: async (system: DeviceSystemMock) => {
          const doc = await system.store.getAccountKeys();
          expect(doc).not.toBeNull();
          expect(doc!.devices["device_B"]).toBeUndefined();
          
          const devB = system.devices["device_B"];
          await expect(unwrapActiveAmk(doc!, "device_B", devB.privB64)).rejects.toThrow();
        }
      }
    },
    RevokedWithRecovery: {
      type: "final",
      meta: {
        test: async (system: DeviceSystemMock) => {
          const doc = await system.store.getAccountKeys();
          expect(doc).not.toBeNull();
          expect(doc!.devices["device_B"]).toBeUndefined();

          const expectedRaw = await system.cryptoProvider.exportSymmetricKey(system.currentAmk);

          // Verify PRF and phrase recovery both still work after rotation/eviction
          const prfRec = await tryRecoverAmkWithPrfKey(doc!, system.prfKey, system.prfMethodId);
          expect(prfRec).not.toBeNull();
          expect(new Uint8Array(prfRec!.amkRaw)).toEqual(new Uint8Array(expectedRaw));

          const unwrappedPhrase = await unwrapAmkById(doc!, "phrase-recovery", system.phrasePrivB64, system.activeAmkId);
          expect(new Uint8Array(unwrappedPhrase)).toEqual(new Uint8Array(expectedRaw));
        }
      }
    }
  }
});

const deviceModel = createModel<DeviceSystemMock>(deviceLifecycleMachine).withEvents({
  REQUEST_JOIN: { exec: async (system) => { await system.executeRequestJoin("device_B", "Device B"); } },
  APPROVE: { exec: async (system) => { await system.executeApprove(system.genesisId, "device_B"); } },
  REJECT: { exec: async (system) => { await system.executeReject("device_B"); } },
  ADD_RECOVERY: { exec: async (system) => { await system.executeAddRecovery(); } },
  REVOKE: { exec: async (system) => { await system.executeRevoke(system.genesisId, "device_B"); } }
});

// ==========================================
// MODEL 2: Keyring Ecosystem Machine
// ==========================================

interface KeyringContext {
  activeAmkVersion: number;
  authorizedDeviceIds: Set<string>;
  recoveryMethodIds: Set<string>;
}

class KeyringSystemMock {
  public store = new MockAccountKeyStore();
  public cryptoProvider = new DeterministicCryptoProvider(42);
  
  public activeAmkVersion = 0;
  public authorizedDeviceIds = new Set<string>();
  public recoveryMethodIds = new Set<string>();
  
  public prfKey!: any;
  public currentAmk!: any;

  constructor() {
    setCryptoProvider(this.cryptoProvider);
  }

  async executeGenesis(deviceId: string, methodId: string) {
    const pair = await generateDeviceKeyPair();
    const pubB64 = await exportDevicePublicKey(pair.publicKey);
    this.prfKey = await generateSymmetricKey(256);
    
    const { doc, rawAmk } = await prepareGenesisDocument(deviceId, "Genesis", pubB64, "cred-gen", this.prfKey, methodId);
    await this.store.setAccountKeys(doc);
    this.currentAmk = await importSymmetricKey(btoa(String.fromCharCode(...new Uint8Array(rawAmk))));
    
    this.activeAmkVersion = 1;
    this.authorizedDeviceIds.add(deviceId);
    this.recoveryMethodIds.add(methodId);
  }

  async executeRotate(revokedId: string) {
    const doc = await this.store.getAccountKeys();
    const newAmk = await generateSymmetricKey(256);
    
    this.activeAmkVersion++;
    const updated = await rotateKeys(revokedId, doc!, this.currentAmk, newAmk, `amk_v${this.activeAmkVersion}`, this.prfKey);
    await this.store.setAccountKeys(updated);
    
    this.currentAmk = newAmk;
    this.authorizedDeviceIds.delete(revokedId);
  }

  async executeAddPrf(methodId: string) {
    const doc = await this.store.getAccountKeys();
    const prfKey = this.prfKey;
    const encryptedLabel = await encryptPayload(this.currentAmk, "PRF recovery");
    
    doc!.recoveryMethods[methodId] = {
      type: "prf",
      encryptedLabel,
      credentialId: "cred-new",
      createdAt: Date.now()
    };
    
    const rawAmk = await this.cryptoProvider.exportSymmetricKey(this.currentAmk);
    const amkB64 = btoa(String.fromCharCode(...new Uint8Array(rawAmk)));
    const plainBytes = new TextEncoder().encode(amkB64) as PlaintextBytes;
    const encryptedPrf = await this.cryptoProvider.encrypt(prfKey, plainBytes);
    const wrappedForPrf = btoa(JSON.stringify({
      ciphertext: uint8ToBase64(encryptedPrf.ciphertext),
      iv: uint8ToBase64(encryptedPrf.iv)
    }));
    doc!.keyring[doc!.activeAmkId][methodId] = wrappedForPrf;
    
    await this.store.setAccountKeys(doc!);
    this.recoveryMethodIds.add(methodId);
  }
}

const keyringMachine = createMachine<KeyringContext>({
  id: "keyringEcosystem",
  initial: "Uninitialized",
  context: {
    activeAmkVersion: 0,
    authorizedDeviceIds: new Set(),
    recoveryMethodIds: new Set()
  },
  states: {
    Uninitialized: {
      on: {
        BOOTSTRAP_GENESIS: {
          target: "Active",
          actions: assign((ctx: any, event: any) => ({
            activeAmkVersion: 1,
            authorizedDeviceIds: new Set(["device_A"]),
            recoveryMethodIds: new Set(["prf-method-A"])
          }))
        }
      },
      meta: {
        test: async (system: KeyringSystemMock) => {
          const doc = await system.store.getAccountKeys();
          expect(doc).toBeNull();
        }
      }
    },
    Active: {
      on: {
        ROTATE_KEYS: {
          target: "Rotated",
          actions: assign((ctx: any) => ({
            activeAmkVersion: ctx.activeAmkVersion + 1,
            authorizedDeviceIds: new Set(Array.from(ctx.authorizedDeviceIds).filter(id => id !== "device_B"))
          }))
        },
        ADD_RECOVERY_PRF: {
          actions: assign((ctx: any) => {
            const next = new Set(ctx.recoveryMethodIds);
            next.add("prf-method-new");
            return { recoveryMethodIds: next };
          })
        }
      },
      meta: {
        test: async (system: KeyringSystemMock) => {
          const doc = await system.store.getAccountKeys();
          expect(doc).not.toBeNull();
          expect(doc!.activeAmkId).toBe(`amk_v${system.activeAmkVersion}`);
          expect(new Set(Object.keys(doc!.devices))).toEqual(system.authorizedDeviceIds);
          expect(new Set(Object.keys(doc!.recoveryMethods))).toEqual(system.recoveryMethodIds);
        }
      }
    },
    Rotated: {
      type: "final",
      meta: {
        test: async (system: KeyringSystemMock) => {
          const doc = await system.store.getAccountKeys();
          expect(doc).not.toBeNull();
          expect(doc!.activeAmkId).toBe(`amk_v${system.activeAmkVersion}`);
          expect(new Set(Object.keys(doc!.devices))).toEqual(system.authorizedDeviceIds);
        }
      }
    }
  }
});

const keyringModel = createModel<KeyringSystemMock>(keyringMachine).withEvents({
  BOOTSTRAP_GENESIS: {
    exec: async (system) => {
      await system.executeGenesis("device_A", "prf-method-A");
    }
  },
  ROTATE_KEYS: {
    exec: async (system) => {
      // Add target device B to evict
      const doc = await system.store.getAccountKeys();
      const pairB = await generateDeviceKeyPair();
      const pubB = await exportDevicePublicKey(pairB.publicKey);
      const updated = await prepareRegistrationData(system.currentAmk, doc!.activeAmkId, "Device B", "device_B", pubB, doc!);
      
      const rawAmk = await system.cryptoProvider.exportSymmetricKey(system.currentAmk);
      const recoveryPubKey = await importDevicePublicKey(pubB);
      const wrapped = await wrapAmk(recoveryPubKey, rawAmk.buffer as ArrayBuffer);
      updated.keyring[doc!.activeAmkId]["device_B"] = wrapped;
      await system.store.setAccountKeys(updated);
      system.authorizedDeviceIds.add("device_B");

      await system.executeRotate("device_B");
    }
  },
  ADD_RECOVERY_PRF: {
    exec: async (system) => {
      await system.executeAddPrf("prf-method-new");
    }
  }
});

// ==========================================
// MODEL 3: Ledger Event Machine
// ==========================================

class LedgerSystemMock {
  public signingPriv!: any;
  public signingPubB64!: string;
  public currentAmk!: any;
  public ledgerEvents: any[] = [];

  constructor() {
    setCryptoProvider(new DeterministicCryptoProvider(42));
  }

  async setup() {
    const pair = await generateIdentityKeyPair();
    this.signingPriv = pair.privateKey;
    this.signingPubB64 = await exportPublicKey(pair.publicKey);
    this.currentAmk = await generateSymmetricKey(256);
  }

  async executePrepareEnvelope(message: string) {
    const action = { message, timestamp: Date.now() };
    const envelope = await prepareAppendEventEnvelope(
      this.signingPriv,
      this.signingPubB64,
      action,
      this.currentAmk
    );
    this.ledgerEvents.push(envelope);
  }

  async executeDecryptValidate() {
    const last = this.ledgerEvents[this.ledgerEvents.length - 1];
    const decrypted = await decryptAndValidateEvent(last.encryptedData, last.iv, this.currentAmk);
    expect(decrypted).not.toBeNull();
    expect(decrypted!.signerPublicKey).toBe(this.signingPubB64);
  }

  async executeRotateSessionKey() {
    this.currentAmk = await generateSymmetricKey(256);
    this.ledgerEvents = [];
  }
}

const ledgerMachine = createMachine({
  id: "ledgerEvent",
  initial: "Empty",
  states: {
    Empty: {
      on: {
        PREPARE_ENVELOPE: "Appending"
      },
      meta: {
        test: async (system: LedgerSystemMock) => {
          expect(system.ledgerEvents.length).toBe(0);
        }
      }
    },
    Appending: {
      on: {
        DECRYPT_VALIDATE: "Snapshot",
        ROTATE_SESSION_KEY: "Empty"
      },
      meta: {
        test: async (system: LedgerSystemMock) => {
          expect(system.ledgerEvents.length).toBeGreaterThan(0);
        }
      }
    },
    Snapshot: {
      on: {
        PREPARE_ENVELOPE: "Appending"
      },
      meta: {
        test: async (system: LedgerSystemMock) => {
          expect(system.ledgerEvents.length).toBeGreaterThan(0);
          const rawEvents = system.ledgerEvents.map((evt, idx) => ({ ...evt, id: `evt-${idx}` }));
          const decrypted = await processLedgerEventSnapshot(rawEvents, system.currentAmk);
          expect(decrypted.length).toBe(system.ledgerEvents.length);
        }
      }
    }
  }
});

const ledgerModel = createModel<LedgerSystemMock>(ledgerMachine).withEvents({
  PREPARE_ENVELOPE: {
    exec: async (system) => {
      await system.executePrepareEnvelope("Test event message payload");
    }
  },
  DECRYPT_VALIDATE: {
    exec: async (system) => {
      await system.executeDecryptValidate();
    }
  },
  ROTATE_SESSION_KEY: {
    exec: async (system) => {
      await system.executeRotateSessionKey();
    }
  }
});

// ==========================================
// TEST EXECUTION RUNNER
// ==========================================

describe("LetUsMeet Cryptographic Core Model Verification Plans", () => {

  describe("1. Device Lifecycle Machine Paths", () => {
    const plans = deviceModel.getSimplePathPlans();
    plans.forEach((plan) => {
      describe(`Path: ${plan.description}`, () => {
        plan.paths.forEach((path) => {
          it(path.description, async () => {
            const system = new DeviceSystemMock();
            await system.setupGenesis();
            await path.test(system);
          });
        });
      });
    });
  });

  describe("2. Keyring Ecosystem Machine Paths", () => {
    const plans = keyringModel.getSimplePathPlans();
    plans.forEach((plan) => {
      describe(`Path: ${plan.description}`, () => {
        plan.paths.forEach((path) => {
          it(path.description, async () => {
            const system = new KeyringSystemMock();
            await path.test(system);
          });
        });
      });
    });
  });

  describe("3. Ledger Event Machine Paths", () => {
    const plans = ledgerModel.getSimplePathPlans();
    plans.forEach((plan) => {
      describe(`Path: ${plan.description}`, () => {
        plan.paths.forEach((path) => {
          it(path.description, async () => {
            const system = new LedgerSystemMock();
            await system.setup();
            await path.test(system);
          });
        });
      });
    });
  });
});
