# LetUsMeet Zero-Knowledge Core: Architecture & Verification Design Document

**Target Audience:** Software Engineers, Cryptographers, & Systems Architects

**Domain:** Applied Cryptography & Distributed Systems (`packages/zero-knowledge/src/core/`)

---

## 1. Introduction: The Problem Space

Standard web applications offload trust and state management to a central server. If a user logs in from a new device, the server issues a session token. If a device is revoked, the server deletes the token.

LetUsMeet operates under a Zero-Knowledge (End-to-End Encrypted) threat model. The server is treated as an untrusted, adversarial datastore. It cannot read user payload data, and it does not hold any encryption keys.

### The Core Challenge

If the server cannot see the keys, how does a user access their data from multiple devices? How do they add a new device? More critically, how do they **revoke** a compromised device without losing access to their own data?

The solution requires a distributed key-management protocol where cryptographic trust is passed directly from device to device. However, orchestrating this protocol over a NoSQL document store (Firestore) introduces a severe risk of concurrency anomalies, replay vulnerabilities, and race conditions.

If Device A revokes Device B at the exact millisecond Device B approves Device C, the system could enter an illegal state where compromised keys remain active. Solving this requires strict protocol design, atomic transition invariants, and rigorous formal verification.

---

## 2. Core Cryptographic Concepts

Before reading the TypeScript implementation, you must understand the vocabulary of the cryptosystem:

* **Active Master Key (AMK):** A symmetric AES-GCM 256-bit key. This is the root of trust. It is used to encrypt user payloads and ledger events. The server never sees this key in plaintext.
* **Device Identity Keys:** Every physical device generates an asymmetric RSA-OAEP keypair.
  * **Public Key:** Uploaded to the server. Anyone can use this to encrypt data *intended* for this device.
  * **Private Key:** Stored securely on the local device hardware (e.g., IndexedDB/Secure Enclave). It never leaves the device.
* **Key Wrapping:** We do not send the AMK over the wire in plaintext. Instead, we "wrap" (encrypt) the AMK using the target device's Public Key. The target device uses its Private Key to "unwrap" the AMK.
* **The Keyring:** A dictionary stored on the server mapping an AMK Version to a list of authorized devices:
  ```json
  "keyring": {
    "amk_v1": {
      "device_A": "wrapped_amk_bytes_base64",
      "device_B": "wrapped_amk_bytes_base64"
    }
  }
  ```

---

## 3. Technical Design: The State Machine

The logic in `packages/zero-knowledge/src/core/deviceLogic.ts` is not just cryptography; it is a distributed state machine. The global state is represented by the `AccountKeysDocument`.

### State Transitions

#### 1. Genesis (`prepareGenesisDocument`)
When a user registers for the first time, the client:
1. Generates the first AMK (`amk_v1`).
2. Generates Device Identity keys.
3. Wraps the AMK using its own Public Key.
4. Uploads the initial `AccountKeysDocument` to the server.

#### 2. Requesting Access (`preparePendingDeviceRequest`)
A new device wants to join. It cannot read the AMK yet.
1. Generates an ephemeral AES key.
2. Creates a `PendingDevice` document.
3. Wraps the ephemeral key for *every currently authorized sponsor device* in the system.

#### 3. Approving Access (`preparePendingDeviceApproval`)
An authorized device (the Sponsor) sees the pending request.
1. Unwraps the ephemeral key using its Private Key.
2. Validates the request.
3. Wraps the current Active Master Key (AMK) using the *new* device's Public Key.
4. Appends the new device to the authorized `devices` list and updates the `keyring`.

#### 4. Revocation and Key Rotation (`rotateKeys`)
When a device is lost or compromised, it must be expelled. You cannot just delete it from the database, because it already knows the previous AMK.
1. The revoking device generates a brand new AMK (`amk_v2`).
2. It encrypts all metadata with the new AMK.
3. It creates a new keyring entry for `amk_v2`.
4. **Crucial Step:** It wraps `amk_v2` for every authorized device *except* the revoked device.
5. Updates the `activeAmkId` to point to `amk_v2`.

### The Event-Sourced Ledger Model (`sessionLogic.ts`)

Beyond device lifecycle management, LetUsMeet implements a completely end-to-end encrypted, event-sourced transaction ledger. The history of actions (creating polls, voting, etc.) is preserved as a sequence of encrypted event envelopes on the untrusted server.

#### 1. Appending to the Ledger (`prepareAppendEventEnvelope`)
When a device performs an action:
1. It signs the action object using its **Identity Signing Private Key (ECDSA)**.
2. It constructs an envelope:
   ```json
   {
     "publicKey": "signer_identity_public_key_base64",
     "signature": "ecdsa_signature_bytes_base64",
     "action": { "type": "CREATE_POLL", "title": "...", "timestamp": 123456789 }
   }
   ```
3. It encrypts this entire envelope string using the **currently active Master Key (AMK)** via AES-GCM.
4. The encrypted data and initialization vector (IV) are appended to the ledger array.

#### 2. Processing and Decrypting Ledger Events (`processLedgerEventSnapshot`)
To build the current application state, a device fetches the entire ledger history:
1. For each event envelope, it decrypts the payload using the AMK active in the event's epoch.
2. It extracts the `publicKey`, `signature`, and `action` from the decrypted JSON.
3. **Critical Security Step:** It mathematically verifies the signature of the action using `verifySignature`. If the signature is invalid or has been tampered with, the event is immediately discarded, protecting the client against rogue event injections from a compromised server.

---

## 4. Verification Strategy: Model-Based Testing

Standard unit tests (e.g., "does the function return a string?") are fundamentally insufficient for mission-critical cryptosystems. To guarantee absolute correctness under adversarial conditions, we utilize a dual-pronged **Model-Based Verification Strategy**: **Model State Path Traversal (XState)** and **Combinatorial Adversarial Fuzzing (Fast-Check)**.

### Phase 1: Model State Path Traversal (XState)

Located in `__tests__/xstatemodel.test.ts`, we utilize `@xstate/test` to model the mathematical behaviors of our state transitions. Instead of writing linear assertions, we define state machines representing our entities:

1. **The Device Lifecycle Machine:** States: `Unregistered` → `Pending` → `Authorized` → `Revoked`
2. **The Keyring Ecosystem Machine:** States: `Uninitialized` → `Active` (AMK v1) → `Rotated` (AMK v2)
3. **The Ledger Event Machine:** States: `Empty` → `Appending` → `Snapshot`

#### Detailed Ledger Event Machine Verification
The `Ledger Event Machine` explicitly verifies our event-sourcing and cryptographic verification rules:
* **`Empty` State:** Asserts that the ledger is empty.
* **`Appending` State:** Triggers event compilation using `prepareAppendEventEnvelope` and verifies that individual event decryption and ECDSA signature validation succeed.
* **`Snapshot` State:** Simulates a client downloading a batch of history, executing `processLedgerEventSnapshot` to decrypt and verify the entire history under the correct active key.

---

### Phase 2: Combinatorial Adversarial Fuzzing (Fast-Check)

Located in `__tests__/fastcheck.test.ts`, `fast-check` acts as our chaos monkey. While XState validates the state path map, `fast-check` aggressively attempts to find any chaotic sequence of actions that breaks our logical preconditions.

#### 1. Standard Ledger & Lifecycle Commands
* **`AppendEventCommand`:** Generates standard signed and encrypted ledger actions using a device's current identity private key and active master key.
* **`ReadSnapshotCommand`:** Decrypts and verifies the signature of all events in the ledger to ensure consistent state reduction.
* **`TimeTravelCommand` (Time Skew):** Advances the global system clock by arbitrary intervals, verifying that expired pending join requests are correctly rejected.

#### 2. Adversarial Byzantine & Chaos Commands
We define `fc.Command` classes representing both standard actions and hostile developer/server behaviors:
* **`ZombieApproveCommand` (Zombie Sponsoring):** Simulates a revoked device attempting to sponsor a newly joining device using its local stale AMK. The test asserts that the cryptographic wraps or transaction boundaries reject it.
* **`ReplayPayloadCommand` (Stale Ciphertext Replay):** Collects historical Firestore states in a memory pool and attempts to replay them to overwrite subsequent keyring records. The test verifies that active AMK version mismatch protections prevent the write.
* **`MutateCiphertextCommand` (Ciphertext Tampering):** Injecting bit flips and corrupting the beginning of base64 wrapped keys. The test verifies that tampering is caught during unwrap, throwing integrity verification exceptions.

#### 3. Strict Security Invariants
After **every single command** executed during a fuzzing sequence (up to 35 continuous random actions), a suite of **Paranoid Invariants** is run to confirm:
* **AMK Isolation Invariant:** Only currently authorized devices hold keyring wraps for the active AMK.
* **Ephemeral Wrap Completeness:** Every active sponsor is properly wrapped in pending requests.
* **Forward Secrecy Invariant (Ledger Protection):** Once a device is revoked and the master key is rotated from `AMK_v1` to `AMK_v2`, the test asserts that `AMK_v1` is **mathematically incapable** of decrypting any subsequent ledger events created in the new epoch.
* **PRF Exclusivity Invariant:** PRF recovery methods continue to successfully unwrap the active master key, even across consecutive multiple rotations.

---

## 5. Development Guidelines: Modifying the Core

If you are a developer modifying the Zero-Knowledge core, you **must not** bypass or weaken these validation suites.

### How to Modify and Add State Logic Safely

1. **Implement Core Logic First:** Update functions in `deviceLogic.ts` or `sessionLogic.ts` using clean, functional TypeScript. Avoid adding hidden side-effects.
2. **Reflect Changes in the XState Abstract Machine (`xstatemodel.test.ts`):**
   * If you introduce a new state (e.g., `Muted`), add it to the `createMachine` definition.
   * Define the transitions to and from the new state.
   * Write rigorous cryptographic assertions in the `meta.test` block of the new state.
   * Add the trigger event and target execution function inside the `.withEvents()` block.
3. **Add Adversarial Commands in the Fuzzer (`fastcheck.test.ts`):**
   * If you add a new capability (e.g., backup recovery key rotation), define a corresponding `fc.Command` class.
   * Program the `check` method to define under what model conditions the command is logically allowed to run.
   * Program the `run` method to execute the database transaction and local crypto routines, asserting that the outcomes match expectations.
   * Append the new command generator to the `fc.commands()` array within the `fc.assert` block.
4. **Enforce the Invariants:** Ensure your changes do not violate the core cryptographic invariants checked by `verifySecurityInvariants`.

---

## 6. How to Run the Verification Suites

All zero-knowledge tests are automated and run using Vitest.

To run the complete verification matrix (including unit tests, integration tests, XState path plans, and fast-check fuzzer runs):

```bash
# Sourcing environment (required on this system)
source ~/.zshrc

# Run the unit and model verification suites
npm run test:unit
```

### Tips for Debugging Fuzzing Failures
If `fast-check` discovers an edge case that violates an invariant:
1. Look at the output failure message. It will display a `seed` and a `counterexample` path.
2. The `counterexample` shows the exact minimal sequence of actions (e.g., `RequestJoin`, `Approve`, `Revoke`, `ZombieApprove`) that triggered the failure.
3. Use the reported seed in `fc.assert(fc.asyncProperty(...), { seed: <seed> })` to locally freeze the execution path, allowing you to step through and debug the specific transaction boundary failure.
