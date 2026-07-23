# Charproof

[![npm version](https://img.shields.io/npm/v/charproof.svg)](https://www.npmjs.com/package/charproof)

Charproof is a standalone zero-knowledge encryption and identity management library built for Cloud Firestore. It is designed to secure application data on the client side before saving to the database, supporting multiple authorized devices, decentralized key sharing, and secure recovery keys via WebAuthn PRF.

## Features

- **Client-Side Zero-Knowledge Encryption**: All application ledger events, user credentials, and metadata are encrypted client-side using WebCrypto.
- **Multi-Device Support**: Securely enroll and authorize secondary devices without exposing decryption keys to the server.
- **Hardware-Backed Recovery**: Securely backup and recover access keys using WebAuthn's PRF extension.
- **Built for Firestore**: Integrates directly with Cloud Firestore stores.

## Installation

Install from the NPM registry:

```bash
npm install charproof
```

## Scripts

### Build

Compile the TypeScript library:

```bash
npm run build
```

### Test

Run the full Vitest suite (includes unit, integration, and fuzz/concurrency checks):

```bash
npm test
```

## Security

Charproof's zero-knowledge guarantees depend on how you deploy it. Before going
to production, read [`SECURITY.md`](./SECURITY.md) and deploy the bundled
[`firestore.rules`](./firestore.rules). In short, you must:

- **Deploy the Firestore security rules** — they enforce per-user isolation and
  append-only, immutable event logs. The guarantees do not hold without them.
- **Set an authorized-signer allowlist** for multi-writer ledgers
  (`session.setAuthorizedSigners(...)`), otherwise any holder of the shared key
  can impersonate another author.
- **Verify devices out-of-band** at enrollment using the 6-digit code
  (`getLocalVerificationCode()` / `approveDeviceAuthorization(d, { expectedVerificationCode })`).
- Understand that **device revocation is forward-only** — it cannot claw back
  data a revoked device already decrypted.

There is no runtime mock/plaintext-crypto switch; the production crypto provider
is WebCrypto unless you explicitly inject one via `initializeZK({ db, auth, cryptoProvider })`.

## Developer & API Guide

Charproof provides a comprehensive API for bootstrapping a zero-knowledge context, managing secondary devices, encrypting transaction logs, and setting up hardware/phrase-based recovery.

### 1. Bootstrapping and Dependency Injection

Before invoking any zero-knowledge operations, configure the database and authentication providers using your application's Firebase instance:

```typescript
import { initializeZK } from 'charproof';
import { getFirestore } from 'firebase/firestore';
import { getAuth } from 'firebase/auth';

// Initialize the zero-knowledge environment
initializeZK({
  db: getFirestore(),
  auth: getAuth()
});
```

#### Configuring the WebAuthn PRF provider (optional)

The built-in PRF provider is configurable via `initializeZK({ prf })` so downstream
apps aren't tied to the default branding or verification posture:

```typescript
initializeZK({
  db: getFirestore(),
  auth: getAuth(),
  prf: {
    rpName: 'Acme Signing',            // display name in the OS passkey prompt (safe to change)
    // rpId: 'acme.example',           // relying-party ID; leave unset to use the origin
    // prfSalt: 'acme-prf-salt-v1',    // PRF evaluation salt
    // userVerification: 'discouraged',// default; pin 'required' for roaming security keys
    // residentKey: 'required',        // default; discoverable passkey (needed for Android GPM)
    // authenticatorAttachment: 'platform' // optional: platform-only UX (excludes roaming keys)
  }
});
```

> **Android requires a discoverable credential.** `residentKey` defaults to
> `'required'` so `create()` produces a **passkey** and Android Chrome routes it
> to Google Password Manager (which carries PRF/`hmac-secret`). Without it, Chrome
> falls back to the legacy security-key chooser and never provisions PRF. This is
> a creation-only setting — it has no effect on recovering existing credentials.
> Set `authenticatorAttachment: 'platform'` for the cleanest platform-only UX
> (note: it excludes roaming security keys); leaving it unset keeps
> resident-capable roaming keys usable.

> **Set-once values.** `prfSalt`, `rpId`, and `userVerification` participate in
> key derivation / credential scoping — changing any of them after credentials
> exist can make previously-sealed data unrecoverable, so pick them once per
> deployment. The default `userVerification: 'discouraged'` matches the value
> earlier versions derived (existing credentials keep recovering) and yields full
> PRF on platform authenticators, which perform user verification regardless of
> the hint. **If your users may enroll PRF recovery on roaming security keys, pin
> `'required'` instead:** any non-`'required'` value lets the authenticator decide
> whether to verify, so a roaming key enrolled without a PIN (uv=0) and later
> given one (uv=1) would derive a different key and silently fail recovery.
> `'required'` forces uv=1 on every ceremony.

### 2. Device Lifecycle and Key Management

Every device enrolling in a user's ZK workspace maintains its own local key pairs (RSA-OAEP for key wrapping, ECDSA for signing) saved in IndexedDB.

#### Requesting Device Enrollment (New Device)
On a new, unauthorized device, trigger the authorization request:

```typescript
import { requestDeviceAuthorization, getActiveAmk } from 'charproof';

try {
  // Generates local keys and registers request in the Account Keystore
  await requestDeviceAuthorization();
  console.log("Device authorization requested. Waiting for approval...");
} catch (error) {
  console.error("Failed to request enrollment:", error);
}
```

#### Approving a Device (Primary Device)
On an already authorized device, listen for and approve pending devices:

```typescript
import { subscribePendingRequests, approveDeviceAuthorization } from 'charproof';

// Listen to pending requests
subscribePendingRequests((pendingDevices) => {
  pendingDevices.forEach(async (device) => {
    // Approve device (re-seals the Account Master Key using the pending device's public key)
    await approveDeviceAuthorization(device);
    console.log(`Approved device: ${device.deviceName}`);
  });
});
```

### 3. ZK Encrypted Ledger Sessions

Charproof lets you record, append, and stream fully client-side encrypted event logs (ledgers) securely.

#### Creating a New Ledger
```typescript
import { createLedgerSession } from 'charproof';

// Creates a new random symmetric key, wrapping it using the active AMK
const { session, ledgerId, ownershipToken } = await createLedgerSession();

// Append encrypted events client-side
await session.appendEvent({
  type: "WRITE_DATA",
  payload: { someSensitiveField: "secrets" }
});
```

#### Loading an Existing Ledger
```typescript
import { getLedgerSession } from 'charproof';

// Load the ledger session using the ledgerId and decrypted symmetric key
const session = await getLedgerSession(ledgerId, {
  shareableKey: decryptedSymmetricKey
});

// Subscribe to real-time decrypted updates
const unsubscribe = session.subscribe((events) => {
  events.forEach((event) => {
    console.log("Decrypted event action:", event.action);
    console.log("Verified Signer:", event.signerPublicKey);
  });
});
```

### 4. Asymmetric Phrase Recovery (BIP39 Mnemonic Backup)

Enables users to safely backup their Account Master Key using a secure 24-word recovery phrase.

> **Recovery is optional at account genesis.** Account creation binds a PRF
> (passkey) recovery custodian when the authenticator supports it, but if PRF
> cannot be provisioned the account is still created as a **device-key-only**
> account so the user is never locked out of sign-up. Such an account has **no
> recovery method** until one is sealed — detect this with
> `getRecoveryStatus()` (`isSealed: false`) and prompt the user to run
> `setupPhraseRecovery()` or `enablePrfRecovery()` right away, because clearing
> local storage before a method exists is unrecoverable.

#### Setting up Recovery Phrase
```typescript
import { setupPhraseRecovery } from 'charproof';

// Generates 24-word phrase, derives symmetric protector, and wraps the AMK
const phrase = await setupPhraseRecovery();
console.log(`Write down your 24-word recovery phrase: "${phrase}"`);
```

#### Recovering the AMK
```typescript
import { recoverAmkWithPhrase } from 'charproof';

// Recovers the AMK from the recovery phrase on a clean device (the account must
// already exist remotely; this restores access to an existing account, it does
// not bootstrap a new one).
const { amk, amkId } = await recoverAmkWithPhrase(phrase);
console.log(`AMK successfully recovered! ID: ${amkId}`);
```

### 5. Core Interfaces & Types Reference

All types and interfaces are exported at the library root and can be imported from `charproof`.

#### `LedgerSession`
The primary interface for client-side encrypted event log interaction:
```typescript
export interface LedgerSession {
  // Appends a new event payload (encrypted client-side with AES-GCM and signed with ECDSA)
  appendEvent(action: any): Promise<void>;
  
  // Subscribes to real-time decrypted updates of the log
  subscribe(onUpdate: (events: DecryptedLedgerEvent[]) => void): () => void;
  
  // Retrieves the first event in the ledger (Genesis)
  getGenesisEvent(): Promise<DecryptedLedgerEvent | null>;
  
  // Exports the raw decrypted symmetric key for the ledger
  exportSessionKey(): string;
  
  // Exports the public signing key associated with the local device identity
  getSignerPublicKey(): string;
}
```

#### `DecryptedLedgerEvent`
Emitted by ledger subscribers when a new event is retrieved and decrypted:
```typescript
export interface DecryptedLedgerEvent {
  action: any;             // The original decrypted payload (e.g. { type: 'VOTE' })
  signerPublicKey: string; // Base64 SPKI public key of the device that authored this event
}
```

#### `AccountKeysDocument`
The schema structure of the root account document stored in Firestore (`/users/{uid}`):
```typescript
export interface AccountKeysDocument {
  activeAmkId: string;                      // The active Account Master Key version ID (e.g., "amk_v1")
  devices: Record<string, DevicePublicKey>;  // Enrolled devices mapped by deviceId
  recoveryMethods: Record<string, RecoveryMethod>; // Configured recovery methods mapped by methodId
  keyring: Record<string, Record<string, string>>; // Matrix of amkId -> deviceId -> wrapped_amk_base64
}
```

#### `PendingDevice`
The structure of a secondary device enrollment request pending primary approval:
```typescript
export interface PendingDevice {
  deviceId: string;
  publicKey: string; // Base64 SPKI RSA Public Key of the new device
  status: 'pending' | 'authorized' | 'rejected';
  createdAt: number;
  encryptedDeviceName: {
    encryptedData: string;
    iv: string;
    wrappedKeys: Record<string, string>; // Maps primary device ID -> encrypted ephemeral symmetric key
  };
}
```

---

## Example Application

Charproof includes a comprehensive interactive example application and end-to-end integration test runner that demonstrates the complete cryptographic lifecycle:

1. **Stage 1 (Genesis)**: Setting up the initial Account Master Key (AMK) and writing encrypted ledger events.
2. **Stage 2 (Enrollment)**: Registering and authorizing a secondary device B to the user's account.
3. **Stage 3 (Decryption)**: Retrieving active AMK on device B and client-side decrypting the ledger events.
4. **Stage 4 (Phrase Recovery)**: Generating a mnemonic phrase, and recovering the AMK on a clean, new device C.

To run the example app:

```bash
npm run example
```