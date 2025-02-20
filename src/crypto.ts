import { createSign, createVerify } from "crypto";

export class CryptoUtils {
  private privateKey: string;
  private publicKey: string;

  constructor(privateKey: string, publicKey: string) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  signData(data: object): string {
    const sign = createSign("SHA256");
    sign.update(JSON.stringify(data));
    sign.end();
    return sign.sign(this.privateKey, "base64");
  }

  verifySignature(data: object, signature: string): boolean {
    const verify = createVerify("SHA256");
    verify.update(JSON.stringify(data));
    verify.end();
    return verify.verify(this.publicKey, signature, "base64");
  }
}
