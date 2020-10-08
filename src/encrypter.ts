/*
The `Encrypter` deals with end-to-end encryption.
It takes any string payload and returns the encrypted version,
also the other way around.
*/

import crypto from "crypto";
import * as hash from "./hash";

const algo = "aes-256-gcm";

interface EncryptedMessage {
  secretDescriptor: string;
  cipher: Buffer;
  initialisationVector: Buffer;
}

export class Encrypter {
  private readonly decryptionSecretsByDescriptor: Record<string, string> = {};

  constructor(
    private readonly encryptionSecret: string,
    decryptionSecrets: string[] = [encryptionSecret]
  ) {
    for (const s of decryptionSecrets) {
      const id = Encrypter.getSecretDescriptor(s);
      this.decryptionSecretsByDescriptor[id] = s;
    }
  }

  static getSecretDescriptor(secret: string): string {
    return hash.md5(secret).slice(0, 4);
  }

  static generateInitialisationVector() {
    return crypto.randomBytes(16);
  }

  static packMessage(message: EncryptedMessage) {
    return [
      message.secretDescriptor,
      message.initialisationVector.toString("base64"),
      message.cipher.toString("base64"),
    ].join(":");
  }

  static unpackMessage(message: string): EncryptedMessage {
    const [secretDescriptor, initialisationVector, cipher] = message.split(":");
    return {
      secretDescriptor,
      initialisationVector: Buffer.from(initialisationVector, "base64"),
      cipher: Buffer.from(cipher, "base64"),
    };
  }

  public encrypt(input: string): string {
    const secretDescriptor = Encrypter.getSecretDescriptor(
      this.encryptionSecret
    );
    const iv = Encrypter.generateInitialisationVector();

    const cipher = crypto.createCipheriv(algo, this.encryptionSecret, iv);

    const encryptedInput = Buffer.concat([
      cipher.update(input, "utf8"),
      cipher.final(),
    ]);

    return Encrypter.packMessage({
      cipher: encryptedInput,
      initialisationVector: iv,
      secretDescriptor: secretDescriptor,
    });
  }

  public decrypt(string: string): string {
    const {
      cipher,
      initialisationVector,
      secretDescriptor,
    } = Encrypter.unpackMessage(string);

    const key = this.decryptionSecretsByDescriptor[secretDescriptor];
    if (!key) {
      throw new Error("Could not decrypt: No matching secret.");
    }

    const decipher = crypto.createDecipheriv(algo, key, initialisationVector);

    return decipher.update(cipher, "hex", "utf8");
  }
}
