import crypto from "crypto";
import { BaseEncryptor } from "./base-encryptor";

const algo = "aes-256-gcm";

export class Encryptor extends BaseEncryptor {

  protected md5(input: string): string {
    const hash = crypto.createHash("md5");
    hash.update(input);
    return hash.digest("hex");
  }
  
  protected generateInitialisationVector(): Buffer {
    return crypto.randomBytes(16);
  }

  protected async _encrypt(
    input: string,
    iv: Buffer,
    key: string
  ): Promise<Buffer> {
    const cipher = crypto.createCipheriv(algo, key, iv);

    const encryptedInput = Buffer.concat([
      cipher.update(input, "utf8"),
      cipher.final(),
    ]);

    return encryptedInput;
  }
  protected async _decrypt(
    cipher: Buffer,
    iv: Buffer,
    key: string
  ): Promise<string> {
    const decipher = crypto.createDecipheriv(algo, key, iv);

    return decipher.update(cipher, "hex", "utf8");
  }
}
