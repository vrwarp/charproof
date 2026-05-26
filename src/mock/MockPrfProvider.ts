import type { PrfProvider } from "../core/interfaces";

export class MockPrfProvider implements PrfProvider {
  async createCredential(
    userId: string,
    _userName: string,
    _displayName: string
  ): Promise<{ credentialId: string; prfResult: Uint8Array }> {
    console.log(`🔑 [Mock PRF] Creating mock WebAuthn passkey credential for user ${userId}`);

    // If in browser context, check if a mock credential already exists for this user on this device
    if (typeof window !== "undefined") {
      try {
        const stored = localStorage.getItem("mock_credentials");
        const creds: Array<{ userId?: string; credentialId: string; prfResultB64: string }> = stored ? JSON.parse(stored) : [];
        
        // Find existing credential either by explicit userId or matching credential ID prefix
        const match = creds.find(c => c.userId === userId || c.credentialId.startsWith(`mock_cred_${userId}_`));
        if (match) {
          console.log(`🔑 [Mock PRF] Reusing existing mock credential for user ${userId}: ${match.credentialId}`);
          const binary = atob(match.prfResultB64);
          const prfResult = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) {
            prfResult[i] = binary.charCodeAt(i);
          }
          return { credentialId: match.credentialId, prfResult };
        }
      } catch (e) {
        console.warn("Failed to check existing mock credentials in localStorage", e);
      }
    }

    const credentialId = `mock_cred_${userId}_${Math.random().toString(36).slice(2, 9)}`;
    
    // Generate a truly random 32-byte PRF result
    const prfResult = new Uint8Array(32);
    if (typeof window !== "undefined" && window.crypto) {
      window.crypto.getRandomValues(prfResult);
    } else {
      for (let i = 0; i < 32; i++) {
        prfResult[i] = Math.floor(Math.random() * 256);
      }
    }

    const prfResultB64 = btoa(String.fromCharCode(...prfResult));

    // Save mock credential to local storage to simulate key storage on this device/hardware
    if (typeof window !== "undefined") {
      try {
        const stored = localStorage.getItem("mock_credentials");
        const creds = stored ? JSON.parse(stored) : [];
        creds.push({ userId, credentialId, prfResultB64 });
        localStorage.setItem("mock_credentials", JSON.stringify(creds));
      } catch (e) {
        console.warn("Failed to write mock credentials to localStorage", e);
      }
    }

    return { credentialId, prfResult };
  }

  async getAssertion(
    credentialIds: string[]
  ): Promise<{ usedCredentialId: string; prfResult: Uint8Array }> {
    let usedCredentialId = credentialIds[0] || "mock_cred_unknown";
    let prfResult = new Uint8Array(32);
    let found = false;

    // In a browser E2E environment, check if the credential exists on this specific "device"
    if (typeof window !== "undefined") {
      try {
        const stored = localStorage.getItem("mock_credentials");
        const creds: Array<{ credentialId: string; prfResultB64: string }> = stored ? JSON.parse(stored) : [];
        
        const match = creds.find(c => credentialIds.includes(c.credentialId));
        if (match) {
          usedCredentialId = match.credentialId;
          const binary = atob(match.prfResultB64);
          prfResult = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) {
            prfResult[i] = binary.charCodeAt(i);
          }
          found = true;
        } else {
          console.warn("🔑 [Mock PRF] Assertion failed: No matching mock credential found on this device.");
          throw new DOMException("The operation was aborted.", "NotAllowedError");
        }
      } catch (e) {
        if (e instanceof DOMException) throw e;
        console.warn("Failed to check mock credentials in localStorage, using deterministic fallback", e);
      }
    }

    if (!found) {
      // Non-browser fallback (e.g. Node.js unit tests)
      for (let i = 0; i < 32; i++) {
        prfResult[i] = (usedCredentialId.charCodeAt(i % usedCredentialId.length) || 0) ^ i;
      }
    }

    console.log(`🔑 [Mock PRF] Resolving assertion for mock passkey credential ${usedCredentialId}`);
    return { usedCredentialId, prfResult };
  }
}
