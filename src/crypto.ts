import { setCryptoProvider } from "./core/crypto";
import { WebCryptoProvider } from "./browser/WebCryptoProvider";

// Set a default browser-based WebCryptoProvider so that consumers can use
// low-level crypto functions without full initializeZK bootstrap.
setCryptoProvider(new WebCryptoProvider());

export * from "./core/crypto";
export {
  uint8ToBase64,
  base64ToUint8,
  uint8ToBase64Url,
  base64UrlToUint8,
  setCryptoProvider
} from "./core/crypto";
