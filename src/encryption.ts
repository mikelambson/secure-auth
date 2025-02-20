import * as argon2 from "argon2";

export class Encryption {
  async hashPassword(password: string): Promise<string> {
    return await argon2.hash(password);
  }

  async verifyPassword(inputPassword: string, storedHash: string): Promise<boolean> {
    return await argon2.verify(storedHash, inputPassword);
  }
}
