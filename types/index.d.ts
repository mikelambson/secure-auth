// @mikelambson/secure-auth/index.d.ts
declare module '@mikelambson/secure-auth' {
    export interface User {
      id: string;
      login: string;
      password: string;
    }
  
    export interface AuthTokens {
      accessToken: string;
      refreshToken: string;
      sessionId: string;
    }
  
    export interface SessionStore {
      saveSession(sessionId: string, userId: string): Promise<boolean>;
      isSessionValid(sessionId: string): Promise<boolean>;
      deleteSession(sessionId: string): Promise<boolean>;
    }
  
    /**
     * Main authentication service for secure user management.
     * Provides JWT generation, password hashing, and session handling.
     * @example
     * ```typescript
     * import { AuthService } from '@mikelambson/secure-auth';
     * import { readFileSync } from 'fs';
     *
     * const privateKey = readFileSync('./private.pem', 'utf8');
     * const publicKey = readFileSync('./public.pem', 'utf8');
     * const auth = new AuthService(privateKey, publicKey);
     *
     * const user = { id: '1', login: 'alice', password: 'hashedPw' };
     * auth.login(user, 'password').then(tokens => console.log(tokens));
     * ```
     */
    export class AuthService {
      /**
       * Creates an AuthService instance with Ed25519 key pair.
       * @param privateKey - Ed25519 private key in PEM format (PKCS8).
       * @param publicKey - Ed25519 public key in PEM format (SPKI).
       * @param sessionStore - Optional session store implementation. Pass null to bypass.
       */
      constructor(privateKey: string, publicKey: string, sessionStore?: SessionStore | null);
  
      /**
       * Registers a new user by hashing their password with Argon2.
       * Store the returned user object in your database.
       * @param user - User data with login and plain-text password.
       * @returns User object with hashed password.
       */
      registerUser(user: User): Promise<User>;
  
      /**
       * Authenticates a user and generates JWT access/refresh tokens.
       * If sessionStore is provided, saves the session automatically.
       * @param user - User object from your DB with hashed password.
       * @param inputPassword - Plain-text password to verify.
       * @returns Access and refresh tokens with session ID.
       * @throws {Error} If credentials are invalid.
       */
      login(user: User, inputPassword: string): Promise<AuthTokens>;
  
      /**
       * Updates a user's password after verifying the old one.
       * @param user - Current user data from DB.
       * @param oldPassword - Current plain-text password.
       * @param newPassword - New plain-text password to hash.
       * @param updatePassword - Callback to save the new hash to your DB.
       * @returns Success message.
       * @throws {Error} If old password is incorrect.
       */
      changePassword(
        user: User,
        oldPassword: string,
        newPassword: string,
        updatePassword: (userId: string, newHashedPassword: string) => Promise<void>
      ): Promise<{ message: string }>;
  
      /**
       * Validates a JWT and checks session validity if sessionStore is set.
       * @param token - JWT to verify (access or refresh).
       * @returns Decoded payload if valid.
       * @throws {Error} If token or session is invalid.
       */
      validateSession(token: string): Promise<{ userId: string; sessionId: string }>;
  
      /**
       * Deletes a session, effectively logging out the user.
       * No-op if sessionStore is null.
       * @param sessionId - Session ID to delete.
       * @throws {Error} If deletion fails.
       */
      logout(sessionId: string): Promise<void>;
  
      /**
       * Sets an HTTP-only, secure session cookie with the token.
       * @param res - Response object with setHeader method (e.g., Express).
       * @param token - JWT to store in cookie.
       */
      setSessionCookie(res: { setHeader: (name: string, value: string) => void }, token: string): void;
  
      /**
       * Clears the session cookie to log out.
       * @param res - Response object with setHeader method.
       */
      clearSession(res: { setHeader: (name: string, value: string) => void }): void;
    }
  
    /**
     * JWT utility for generating and verifying EdDSA-signed tokens.
     * @example
     * ```typescript
     * import { JWT } from '@mikelambson/secure-auth';
     * const jwt = new JWT(privateKey, publicKey);
     * jwt.generateTokens('user123', async (sid, uid) => true).then(console.log);
     * ```
     */
    export class JWT {
      constructor(privateKey: string, publicKey: string);
      generateTokens(
        userId: string,
        storeSession: (sessionId: string, userId: string) => Promise<boolean>
      ): Promise<AuthTokens>;
      verifyToken(
        token: string,
        isSessionValid: (sessionId: string) => Promise<boolean>
      ): Promise<{ userId: string; sessionId: string }>;
    }
  
    /**
     * Encryption utility using Argon2 for password hashing.
     */
    export class Encryption {
      hashPassword(password: string): Promise<string>;
      verifyPassword(password: string, hash: string): Promise<boolean>;
    }
  
    /**
     * WebAuthn utility for passkey authentication.
     */
    export class WebAuthn {
      generateChallenge(
        userId: string,
        rpID: string,
        userVerification: 'preferred' | 'required' | 'discouraged',
        storeChallenge: (userId: string, challenge: string) => Promise<void>
      ): Promise<any>;
      verifyPasskey(
        response: any,
        userId: string,
        expectedRPID: string,
        expectedOrigin: string,
        getStoredChallenge: (userId: string) => Promise<string | null>,
        getCredential: (userId: string) => Promise<any>
      ): Promise<any>;
    }
  }