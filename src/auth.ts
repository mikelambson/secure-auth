import { JWT } from "./jwt.js";
import { Encryption } from "./encryption.js";
import { WebAuthn } from "./webauthn.js";
import dotenv from 'dotenv';
import { join } from 'path';
import { readFileSync } from 'fs';

interface User { id: string; login: string; password: string; }
interface AuthTokens { accessToken: string; refreshToken: string; sessionId: string; }

interface SessionStore {
  saveSession(sessionId: string, userId: string): Promise<boolean>;
  isSessionValid(sessionId: string): Promise<boolean>;
  deleteSession(sessionId: string): Promise<boolean>;
}

export class AuthService {
  private jwt: JWT;
  private encryption: Encryption;
  private webauthn: WebAuthn;
  private sessionStore: SessionStore;

  constructor(sessionStore: SessionStore, privateKey?: string, publicKey?: string ) {
   // Load .env if present
   const envPath = join(process.cwd(), '.env');
   dotenv.config({ path: envPath });

   // Default key file locations
   const defaultPrivateKeyPath = join(process.cwd(), '.secure-auth', 'private-key.pem');
   const defaultPublicKeyPath = join(process.cwd(), '.secure-auth', 'public-key.pem');
   const privateKeyPath = process.env.JWT_PRIVATE_KEY || defaultPrivateKeyPath;
   const publicKeyPath = process.env.JWT_PUBLIC_KEY || defaultPublicKeyPath;

   // Read keys—fail if missing
   try {
     privateKey = readFileSync(privateKeyPath, 'utf8');
     publicKey = readFileSync(publicKeyPath, 'utf8');
   } catch (error) {
     throw new Error(`Failed to load keys from ${privateKeyPath} or ${publicKeyPath}. Run 'npx secure-auth init' or set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY in .env`);
   }


    this.jwt = new JWT(privateKey, publicKey); // Pass raw strings
    this.encryption = new Encryption();
    this.webauthn = new WebAuthn();
    this.sessionStore = sessionStore;
  }

  /**
   * Register a new user by hashing their password.
   */
  async registerUser(user: { login: string; password: string }) {
    const hashedPassword = await this.encryption.hashPassword(user.password);
    return { ...user, password: hashedPassword }; // Save in DB externally
  }

  /**
   * Change an existing user's password.
   */
  async changePassword(
    user: User,
    oldPassword: string,
    newPassword: string,
    updatePassword: (userId: string, newHashedPassword: string) => Promise<void>
  ) {
    if (!(await this.encryption.verifyPassword(oldPassword, user.password))) {
      throw new Error("Current password is incorrect.");
    }

    const newHashedPassword = await this.encryption.hashPassword(newPassword);
    await updatePassword(user.id, newHashedPassword);

    return { message: "Password successfully changed." };
  }

  /**
   * Authenticate a user and generate access/refresh tokens.
   */
  async login(
    user: { id: string; login: string; password: string },
    inputPassword: string
  ) {
    if (!(await this.encryption.verifyPassword(inputPassword, user.password))) {
      throw new Error("Invalid credentials");
    }

    return this.jwt.generateTokens(user.id, async (sessionId, userId) => {
      return await this.sessionStore.saveSession(sessionId, userId);
    });
  }

  /**
   * Generate a WebAuthn challenge for passkey registration.
   */
  async registerPasskey(
    userId: string,
    rpID: string,
    userVerification: "preferred" | "required" | "discouraged",
    storeChallenge: (userId: string, challenge: string) => Promise<void>
  ) {
    return this.webauthn.generateChallenge(
      userId,
      rpID,
      userVerification,
      storeChallenge
    );
  }

  /**
   * Verify a WebAuthn passkey response.
   */
  async verifyPasskey(
    response: any,
    userId: string,
    expectedRPID: string,
    expectedOrigin: string,
    getStoredChallenge: (userId: string) => Promise<string | null>,
    getCredential: (userId: string) => Promise<any>
  ) {
    return this.webauthn.verifyPasskey(
      response,
      userId,
      expectedRPID,
      expectedOrigin,
      getStoredChallenge,
      getCredential
    );
  }

  /**
   * Validate a session token (Ensures JWT is valid and session exists).
   */
  async validateSession(token: string) {
    return this.jwt.verifyToken(token, async (sessionId) => {
      return await this.sessionStore.isSessionValid(sessionId);
    });
  }

  async refresh(refreshToken: string) {
    return this.jwt.refreshToken(
      refreshToken,
      this.sessionStore ? (sessionId, userId) => this.sessionStore.saveSession(sessionId, userId) : async () => true
    );
  }

  /**
   * Logout: Delete session from database (Invalidates token).
   */
  async logout(sessionId: string) {
    const success = await this.sessionStore.deleteSession(sessionId);
    if (!success) {
      throw new Error("Failed to log out.");
    }
  }

  /**
   * Set a session cookie (Handles Express, Fastify, Koa, or raw Node.js).
   */
  setSessionCookie(
    res: { setHeader: (name: string, value: string) => void },
    token: string
  ) {
    res.setHeader(
      "Set-Cookie",
      `authToken=${token}; HttpOnly; Secure; Path=/;`
    );
  }

  /**
   * Clear a user's session cookie (Logout).
   */
  clearSession(res: { setHeader: (name: string, value: string) => void }) {
    res.setHeader(
      "Set-Cookie",
      `authToken=; HttpOnly; Secure; Path=/; Max-Age=0;`
    );
  }
}
