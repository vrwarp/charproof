# Charproof

[![npm version](https://img.shields.io/npm/v/charproof.svg)](https://www.npmjs.com/package/charproof)

Charproof is a standalone zero-knowledge encryption and identity management library built for Cloud Firestore. It is designed to secure application data on the client side before saving to the database, supporting multiple authorized devices and secure recovery keys via WebAuthn PRF.

## Features

- **Client-Side Zero-Knowledge Encryption**: All scheduling, responses, and user metadata are encrypted on the client side.
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