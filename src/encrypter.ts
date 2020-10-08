/*
The `Encrypter` deals with end-to-end encryption.
It takes any string payload and returns the encrypted version,
also the other way around.
*/

import crypto from "crypto";
import * as hash from "./hash";

const algo = "aes-256-gcm";

export class Encrypter {
  private readonly decryptionSecretsById: Record<string, string> = {};

  private readonly cipher;

  constructor(
    private readonly encryptionSecret: string,
    decryptionSecrets: string[],
  ) {
    for (const s of decryptionSecrets) {
      const id = Encrypter.secretToId(s);
      this.decryptionSecretsById[id] = s;
    }

    this.cipher = crypto.createCipheriv(
      algo,
      encryptionSecret,
    );
  }

  static secretToId(secret: string): string {
    return hash.md5(secret).slice(0, 4);
  }

  public encrypt(input: string): string {
    const id = Encrypter.secretToId(this.encryptionSecret);

    let encryptedInput = this.cipher.update(input, "utf8", "hex");
    encryptedInput += this.cipher.final("hex");

    return `${id}:${encryptedInput}`;
  }

  public decrypt(string: string): string {
    const indexOfFirstColon = string.indexOf(":");
    const id = string.slice(0, indexOfFirstColon);
    const cipher = string.slice(indexOfFirstColon + 1);

    const key = this.decryptionSecretsById[id];

    const decipher = crypto.createDecipheriv(
      algo,
      key,
    );

    return decipher.update(cipher, "hex", "utf8");
  }
}
