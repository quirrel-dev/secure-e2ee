import crypto from "crypto";
import { BaseEncryptor } from "./base-encryptor";

const algo = "aes-256-gcm";

export class Encryptor extends BaseEncryptor {
  protected md5(input: string): string {
    const hash = crypto.createHash("md5");
    hash.update(input);
    return hash.digest("hex");
  }

  generateInitialisationVector(): Buffer {
    return crypto.randomBytes(16);
  }

  protected async _encrypt(
    input: string,
    iv: Uint8Array,
    key: string
  ): Promise<Uint8Array> {
    const cipher = crypto.createCipheriv(algo, key, iv, {
      authTagLength: 16,
    });

    const encryptedInput = Buffer.concat([
      cipher.update(input, "utf8"),
      cipher.final(),
      cipher.getAuthTag(),
    ]);

    return encryptedInput;
  }

  protected async _decrypt(
    cipher: Uint8Array,
    iv: Uint8Array,
    key: string
  ): Promise<string> {
    const decipher = crypto.createDecipheriv(algo, key, iv, {
      authTagLength: 16,
    });

    decipher.setAuthTag(cipher.slice(cipher.byteLength - 16));

    return decipher.update(
      cipher.slice(0, cipher.byteLength - 16),
      "hex",
      "utf8"
    );
  }
}

export default Encryptor;
