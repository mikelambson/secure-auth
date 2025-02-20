import {
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
  } from "@simplewebauthn/server";
  
  export class WebAuthn {
    /**
     * Generate a WebAuthn authentication challenge.
     * @param userId - Unique ID of the user.
     * @param rpID - Relying Party ID (usually the domain).
     * @param userVerification - "preferred", "required", or "discouraged".
     * @param storeChallenge - Function to store challenge (Redis, session, etc.).
     * @returns WebAuthn challenge options.
     */
    async generateChallenge(
      userId: string,
      rpID: string,
      userVerification: "preferred" | "required" | "discouraged",
      storeChallenge: (userId: string, challenge: string) => Promise<void>
    ) {
      const challengeOptions = await generateAuthenticationOptions({
        rpID,
        userVerification,
      });
  
      // Store challenge for this user (passed-in function handles storage)
      await storeChallenge(userId, challengeOptions.challenge);
      
      return challengeOptions;
    }
  
    /**
     * Verify a WebAuthn passkey response.
     * @param response - WebAuthn response from client.
     * @param userId - Unique user ID.
     * @param expectedRPID - Expected relying party ID.
     * @param expectedOrigin - Expected origin (website URL).
     * @param getStoredChallenge - Function to retrieve stored challenge.
     * @param getCredential - Function to retrieve stored credential.
     * @returns Verification result (valid or not).
     */
    async verifyPasskey(
      response: any,
      userId: string,
      expectedRPID: string,
      expectedOrigin: string,
      getStoredChallenge: (userId: string) => Promise<string | null>,
      getCredential: (userId: string) => Promise<any>
    ) {
      const expectedChallenge = await getStoredChallenge(userId);
      if (!expectedChallenge) {
        throw new Error("Challenge not found or expired.");
      }
  
      const storedCredential = await getCredential(userId);
      if (!storedCredential) {
        throw new Error("Credential not found.");
      }
  
      return verifyAuthenticationResponse({
        response,
        expectedRPID,
        expectedOrigin,
        expectedChallenge,
        credential: storedCredential, // Must be the full stored credential
      });
    }
  }
  