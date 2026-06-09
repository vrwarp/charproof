# Charproof Security Model & Operator Guide

Charproof is a client-side zero-knowledge library. Its guarantees depend on both
the library **and** how you deploy it. This document describes the trust model,
the operator responsibilities, and the hardening changes in this release.

## 1. You MUST deploy the Firestore security rules

The confidentiality of ciphertext is enforced in the client, but **access
control and document integrity are enforced by Firestore security rules**. A
reference ruleset is shipped as [`firestore.rules`](./firestore.rules). Without
equivalent rules the zero-knowledge model does not hold (any user could read or
overwrite another user's key material).

Key properties the rules enforce:

- `users/{uid}/**` (account keys, keystore, pending devices) are **owner-only**.
- `polls/{ledgerId}` and their `events` are **append-only and immutable** —
  events cannot be updated or deleted once written.
- There is **no global chaff-pool document** and **no cross-tenant write path**.

## 2. Authenticate event authorship (multi-writer ledgers)

An event envelope carries the signer's own public key, so a signature only
proves "the author held *some* private key" — not *which* participant. Anyone
holding the shared symmetric key could otherwise mint a keypair and impersonate
another author.

For any ledger with more than one writer, pass the set of authorized signer
public keys so unauthorized authors are rejected during validation:

```ts
const session = await getLedgerSession(ledgerId, { shareableKey });
session.setAuthorizedSigners(authorizedPublicKeys); // base64 SPKI keys
session.subscribe(onUpdate, onError);
```

When no allowlist is set, the library accepts any well-signed event
(single-writer / trust-all mode). Maintain the allowlist from your application's
membership semantics (e.g. an admin-signed membership event).

> Residual limitation: Firestore cannot verify signatures, so authorship is
> enforced **only** on the client during decryption/validation. Treat the
> allowlist as the source of truth.

## 3. Verify devices out-of-band during enrollment

When approving a new device, confirm the 6-digit verification code shown on both
devices before granting it the Account Master Key. This blocks a man-in-the-
middle who injected their own public key into the pending request:

```ts
// On the enrolling device:
const code = await getLocalVerificationCode();

// On the approving device, after the user compares codes:
await approveDeviceAuthorization(pendingDevice, { expectedVerificationCode: code });
```

If `expectedVerificationCode` is omitted, approval proceeds without the check
(backward compatible) — but you should always supply it in production UIs.

## 4. Revocation semantics (forward-only)

`revokeDevice` rotates the Account Master Key, re-wraps it for the remaining
devices/recovery methods, and now **purges the revoked device from every keyring
version** (not just the active one), so it can no longer unwrap any historical
AMK.

However, revocation **cannot** retroactively protect data the revoked device
already decrypted while it was authorized. Ledger/keystore payloads encrypted
under a key the device already held remain readable to it if it exfiltrated that
key. Revocation protects **future** data. If you need to deny access to existing
data, you must additionally rotate the underlying ledger symmetric keys and
re-share them with the remaining participants.

## 5. Decoy (chaff) writes are tenant-local and opt-in

Decoy writes (to obscure which ledger changed) are **disabled by default** and,
when enabled, only target the **caller's own** ledgers:

```ts
import { FirestoreLedgerEventStore, setSessionProviders, setLedgerDecoyPool } from 'charproof';

setSessionProviders({ ledgerEventStore: new FirestoreLedgerEventStore({ decoyPool: myLedgerIds }) });
// or update dynamically:
setLedgerDecoyPool(myLedgerIds);
```

The previous implementation wrote decoys into a globally-shared pool of *other
users'* ledgers, which leaked the active-ledger set and required permissive
cross-tenant write rules. That behavior has been removed.

## 6. Key-derivation hardening (migration notes)

- **PBKDF2** now uses `600,000` iterations (OWASP 2023) with a **per-record
  random salt** instead of a shared constant. Salts are stored alongside the
  ciphertext. Phrase-recovery entries created before this change are still
  readable via a legacy fallback (constant salt, 100k iterations).
- **WebAuthn PRF** recovery keys now use the full **256 bits** of PRF output
  instead of truncating to 128. PRF recovery material sealed by older versions
  (128-bit) will not match; re-enable PRF recovery (`enablePrfRecovery`) on an
  authorized device to re-seal under the new 256-bit key.

## 7. No runtime mock / plaintext crypto in production

There is **no** ambient `window.__MOCK_ZK` switch. The only crypto provider is
the WebCrypto-backed one unless you explicitly inject an alternative for testing
via `initializeZK({ db, auth, cryptoProvider })`. The plaintext mock providers
are no longer part of the published package.

## Reporting

Please report security issues via the repository's
[issue tracker](https://github.com/vrwarp/charproof/issues).
