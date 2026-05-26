# Charproof API Reference Guide

This document provides a comprehensive, authoritative API reference guide for the **Charproof** Zero-Knowledge library. 

---

## 1. Bootstrapping & Setup

### `initializeZK(providers)`
Bootstraps the global zero-knowledge environment. This must be called before executing any other library functions.

```typescript
function initializeZK(providers: {
  db: Firestore;
  auth: Auth;
}): void;
```

#### Parameters:
- `providers.db`: An active Firebase Firestore database instance.
- `providers.auth`: An active Firebase Authentication instance.

#### Example:
```typescript
import { initializeZK } from 'charproof';
import { db, auth } from './myFirebaseSetup';

initializeZK({ db, auth });
```

---

## 2. Device Management & Decentralized Keyrings

Every authorized device maintains its own asymmetric RSA keypair (for AMK wrapping) and an ECDSA keypair (for signing events) saved persistently in IndexedDB.

### `getActiveAmk()`
Retrieves or initializes the Account Master Key (AMK).
- On **Genesis** (fresh account), it generates a new AMK and seals it.
- On **secondary devices**, it automatically retrieves and decrypts the active AMK from the keyring if authorized.

```typescript
function getActiveAmk(): Promise<{
  amk: AesGcmKey;
  amkId: string;
}>;
```

#### Returns:
- `amk`: An AES-GCM 256-bit symmetric key handle.
- `amkId`: The version ID string of the key (e.g. `"amk_v1"`).

---

### `requestDeviceAuthorization()`
Registers a new, unauthorized device's public key in the account keystore, requesting approval from existing authorized devices.

```typescript
function requestDeviceAuthorization(): Promise<void>;
```

---

### `approveDeviceAuthorization(pendingDevice)`
Approves a pending enrollment request by re-sealing the active Account Master Key (AMK) using the new device's registered RSA public key and updating the keyring.

```typescript
function approveDeviceAuthorization(pendingDevice: PendingDevice): Promise<void>;
```

#### Parameters:
- `pendingDevice`: The enrollment request details fetched from the pending queue.

#### Example:
```typescript
import { subscribePendingRequests, approveDeviceAuthorization } from 'charproof';

subscribePendingRequests((devices) => {
  devices.forEach(async (device) => {
    await approveDeviceAuthorization(device);
    console.log(`Successfully enrolled device: ${device.deviceName}`);
  });
});
```

---

### `revokeDevice(deviceId)`
Revokes a device by removing its public key, generating a **new Account Master Key (AMK)**, re-sealing it for all remaining devices, and rotating the keyring.

```typescript
function revokeDevice(deviceId: string): Promise<void>;
```

#### Parameters:
- `deviceId`: The unique ID of the device to revoke.

---

## 3. Zero-Knowledge Ledger Sessions

Ledger sessions encrypt all data client-side before sending to Firestore. The session key is protected by the user's active AMK.

### `createLedgerSession()`
Creates a new client-side encrypted ledger session.

```typescript
function createLedgerSession(): Promise<CreateLedgerResult>;
```

#### Returns:
- `ledgerId`: The generated unique string ID of the ledger.
- `ownershipToken`: Cryptographic token allowing recovery of ownership.
- `session`: The active `LedgerSession` instance.

---

### `getLedgerSession(ledgerId, options)`
Loads and initializes an existing client-side encrypted ledger session.

```typescript
function getLedgerSession(
  ledgerId: string,
  options?: {
    shareableKey?: string;
    ownershipToken?: string;
  }
): Promise<LedgerSession>;
```

#### Parameters:
- `ledgerId`: The unique ID of the ledger to load.
- `options.shareableKey`: The decrypted symmetric session key (if shared via link).
- `options.ownershipToken`: The ownership recovery token.

#### Returns:
- A promise resolving to the decrypted, active `LedgerSession` instance.

#### Example:
```typescript
import { getLedgerSession } from 'charproof';

const session = await getLedgerSession("my-ledger-id", {
  shareableKey: "symmetric-session-key-base64"
});

// Stream real-time decrypted updates
const unsubscribe = session.subscribe((events) => {
  events.forEach(e => console.log("Decrypted Event:", e.action));
});
```

---

## 4. Key Recovery & Phrase Backup

### `setupPhraseRecovery()`
Configures phrase-based key recovery. Generates a 24-word BIP39 mnemonic, derives a protector, and seals a recovery RSA private key.

```typescript
function setupPhraseRecovery(): Promise<string>;
```

#### Returns:
- A promise resolving to the raw 24-word BIP39 mnemonic phrase string.

---

### `recoverAmkWithPhrase(mnemonic)`
Recovers the Account Master Key (AMK) using the 24-word recovery phrase on a completely new, clean device.

```typescript
function recoverAmkWithPhrase(mnemonic: string): Promise<{
  amk: AesGcmKey;
  amkId: string;
}>;
```

#### Parameters:
- `mnemonic`: The 24-word BIP39 recovery phrase string.

#### Returns:
- The recovered active `AesGcmKey` handle and its version `amkId`.
