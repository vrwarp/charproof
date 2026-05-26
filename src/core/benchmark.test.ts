import { test } from "vitest";
import { generateSymmetricKey, generateIdentityKeyPair, exportPublicKey, setCryptoProvider } from "./crypto";
import { prepareAppendEventEnvelope, processLedgerEventSnapshot } from "./sessionLogic";
import { WebCryptoProvider } from "../browser/WebCryptoProvider";
import * as nodeCrypto from "node:crypto";

if (!globalThis.crypto) {
  (globalThis as any).crypto = nodeCrypto.webcrypto;
}
if (!globalThis.window) {
  (globalThis as any).window = globalThis;
}
setCryptoProvider(new WebCryptoProvider());

test("benchmark processLedgerEventSnapshot", async () => {
  const symmetricKey = await generateSymmetricKey(256);
  const keyPair = await generateIdentityKeyPair();
  const pubB64 = await exportPublicKey(keyPair.publicKey);

  const numEvents = 500;
  const rawEvents = [];

  for (let i = 0; i < numEvents; i++) {
    const action = { type: 'VOTE', payload: { id: i } };
    const encryptedData = await prepareAppendEventEnvelope(
      keyPair.privateKey,
      pubB64,
      action,
      symmetricKey
    );
    rawEvents.push({
      encryptedData: encryptedData.encryptedData,
      iv: encryptedData.iv,
      id: `id-${i}`
    });
  }

  const start = performance.now();
  await processLedgerEventSnapshot(rawEvents, symmetricKey);
  const end = performance.now();
  console.log(`[BENCHMARK] Decryption of ${numEvents} events took: ${(end - start).toFixed(2)} ms`);
});
