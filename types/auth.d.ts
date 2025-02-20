declare module "@mikelambson/secure-auth" {
    export interface User {
      id: string;
      login: string;
      password: string;
    }
  
    export interface AuthTokens {
      accessToken: string;
      refreshToken: string;
    }
  
    export class AuthService {
      constructor(secret: string);
      login(user: User, inputPassword: string): Promise<AuthTokens>;
      changePassword(
        user: User,
        oldPassword: string,
        newPassword: string,
        updatePassword: (userId: string, newHashedPassword: string) => Promise<void>
      ): Promise<{ message: string }>;
    }
  }
  