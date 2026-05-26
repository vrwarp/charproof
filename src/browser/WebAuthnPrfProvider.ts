import type { PrfProvider } from "../core/interfaces";

export class WebAuthnPrfProvider implements PrfProvider {
  async createCredential(
    userId: string,
    userName: string,
    displayName: string
  ): Promise<{ credentialId: string; prfResult: Uint8Array }> {
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const createOptions: CredentialCreationOptions = {
      publicKey: {
        challenge,
        rp: { name: "LetUsMeet" },
        user: {
          id: new TextEncoder().encode(userId),
          name: userName,
          displayName: displayName
        },
        pubKeyCredParams: [
          { alg: -7, type: "public-key" },
          { alg: -257, type: "public-key" }
        ],
        authenticatorSelection: { userVerification: "discouraged" },
        extensions: {
          prf: { eval: { first: new TextEncoder().encode("LetUsMeet-PRF-Salt-v1") } }
        } as any
      }
    };

    const credential = (await navigator.credentials.create(createOptions)) as any;
    if (!credential) throw new Error("Failed to create PRF credential.");

    const results = credential.getClientExtensionResults();
    if (results.prf && results.prf.results && results.prf.results.first) {
      const prfResult = new Uint8Array(results.prf.results.first);
      const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
      return { credentialId, prfResult };
    }

    const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
    const assertion = await this.getAssertion([credentialId]);
    return { credentialId, prfResult: assertion.prfResult };
  }

  async getAssertion(
    credentialIds: string[]
  ): Promise<{ usedCredentialId: string; prfResult: Uint8Array }> {
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const getOptions: CredentialRequestOptions = {
      publicKey: {
        challenge,
        allowCredentials: credentialIds.map(id => ({
          id: Uint8Array.from(atob(id), c => c.charCodeAt(0)),
          type: "public-key" as const
        })),
        userVerification: "discouraged",
        extensions: {
          prf: { eval: { first: new TextEncoder().encode("LetUsMeet-PRF-Salt-v1") } }
        } as any
      }
    };

    const assertion = (await navigator.credentials.get(getOptions)) as any;
    const results = assertion.getClientExtensionResults();

    if (!results.prf || !results.prf.results || !results.prf.results.first) {
      throw new Error("PRF evaluation failed or not supported by authenticator.");
    }

    const prfResult = new Uint8Array(results.prf.results.first);
    const usedCredentialId = btoa(String.fromCharCode(...new Uint8Array(assertion.rawId)));
    return { usedCredentialId, prfResult };
  }
}
