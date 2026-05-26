import { generateSymmetricKey, generateIdentityKeyPair, exportPublicKey } from "./crypto";
import { prepareAppendEventEnvelope, processLedgerEventSnapshot } from "./sessionLogic";

async function run() {
  const symmetricKey = await generateSymmetricKey();
  const keyPair = await generateIdentityKeyPair();
  const pubB64 = await exportPublicKey(keyPair.publicKey);

  const numEvents = 100;
  const rawEvents = [];

  console.log(`Generating ${numEvents} mock events...`);
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

  console.log("Running baseline benchmark...");
  const start = performance.now();
  await processLedgerEventSnapshot(rawEvents, symmetricKey);
  const end = performance.now();
  console.log(`Decryption took: ${(end - start).toFixed(2)} ms`);
}

run().catch(console.error);
