declare module "@mikelambson/secure-auth" {
    /** WebAuthn challenge response options */
    export interface WebAuthnChallenge {
      challenge: string;
      rpID: string;
      userVerification: "preferred" | "required" | "discouraged";
    }
  
    /** WebAuthn verification response */
    export interface WebAuthnResponse {
      userId: string;
      response: any; // WebAuthn API response object
    }
  
    /** Defines WebAuthn authentication service */
    export class WebAuthn {
      /** Generates a WebAuthn authentication challenge */
      generateChallenge(
        userId: string,
        rpID: string,
        userVerification: "preferred" | "required" | "discouraged",
        storeChallenge: (userId: string, challenge: string) => Promise<void>
      ): Promise<WebAuthnChallenge>;
  
      /** Verifies a WebAuthn authentication response */
      verifyPasskey(
        response: WebAuthnResponse,
        userId: string,
        expectedRPID: string,
        expectedOrigin: string,
        getStoredChallenge: (userId: string) => Promise<string | null>,
        getCredential: (userId: string) => Promise<any>
      ): Promise<boolean>;
    }
  }
  