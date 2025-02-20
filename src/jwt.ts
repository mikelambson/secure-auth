import jwt from "jsonwebtoken";
import * as fs from "fs";
import * as path from "path";
import { v4 as uuidv4 } from "uuid";

export class JWT {
  private privateKey: string;
  private publicKey: string;

  constructor(privateKeyPath?: string, publicKeyPath?: string) {
    // Load keys from files (or environment variables)
    this.privateKey = privateKeyPath
      ? fs.readFileSync(path.resolve(privateKeyPath), "utf8")
      : process.env.JWT_PRIVATE_KEY!;

    this.publicKey = publicKeyPath
      ? fs.readFileSync(path.resolve(publicKeyPath), "utf8")
      : process.env.JWT_PUBLIC_KEY!;

    if (!this.privateKey || !this.publicKey) {
      throw new Error("JWT private and public keys must be provided.");
    }
  }

  /**
   * Generates access & refresh JWTs tied to a session.
   * @param userId - The user's unique ID
   * @param storeSession - A function that stores session in the DB
   * @returns Object containing accessToken, refreshToken, and sessionId
   */
  async generateTokens(
    userId: string,
    storeSession: (sessionId: string, userId: string) => Promise<boolean>
  ) {
    const sessionId = uuidv4(); // Generate a new session identifier

    const sessionStored = await storeSession(sessionId, userId);
    if (!sessionStored) {
      throw new Error("Failed to store session in database.");
    }

    const payload = { userId, sessionId };

    const accessToken = jwt.sign(payload, this.privateKey, {
      algorithm: "EdDSA",
      expiresIn: "15m",
    });

    const refreshToken = jwt.sign(payload, this.privateKey, {
      algorithm: "EdDSA",
      expiresIn: "7d",
    });

    return { accessToken, refreshToken, sessionId };
  }

  /**
   * Verifies a JWT and ensures the session is still valid.
   * @param token - The JWT token to verify
   * @param isSessionValid - A function to check session validity
   * @returns Decoded payload if valid, else throws an error
   */
  async verifyToken(
    token: string,
    isSessionValid: (sessionId: string) => Promise<boolean>
  ) {
    const decoded = jwt.verify(token, this.publicKey, { algorithms: ["EdDSA"] });

    if (!decoded || typeof decoded !== "object" || !decoded.sessionId) {
      throw new Error("Invalid token.");
    }

    // Check if session exists in DB
    const sessionValid = await isSessionValid(decoded.sessionId);
    if (!sessionValid) {
      throw new Error("Session expired or invalid.");
    }

    return decoded;
  }
}
