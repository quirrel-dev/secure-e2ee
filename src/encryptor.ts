/*
The `Encrypter` deals with end-to-end encryption.
It uses aes-256-gcm, which is a symmetric encryption algorithm.

It uses a so-called "initialisation vector":
a random, non-predictable value
that makes encryption unpredictable
(kind of like "salts" in hash functions).

initialisation_vector = generate_random_string()

encrypted = encrypt(
  input,
  secret,
  initialisation_vector
)

send_over_the_wire(encrypted, initialisation_vector)

decrypted = decrypt(
  cipher_text,
  secret,
  initialisation_vector
)

decrypted === input // 🎉

That would already be enough to simply encrypt our messages,
but there's still one problem:
What happens when the secret needs to be changed, e.g. because it has been leaked?
If there was only one secret, all previously encrypted messages
would become unreadable.

To prevent this, the Encrypter has so-called decryption-only-secrets.
If a secret needs to be cycled out, you can add it to the decryption-only-secrets,
to allow decryption of previously-encrypted messages.

To make this work, we also send a small secret
descriptor over the networks, that indicates
which secret should be used for decryption.
*/

import crypto from "crypto";
import * as hash from "./hash";

const algo = "aes-256-gcm";

interface EncryptedMessage {
  secretDescriptor: string;
  cipher: Buffer;
  initialisationVector: Buffer;
}

function isValidSecret(string: String): boolean {
  return string.length === 32;
}

export function getSecretDescriptor(secret: string): string {
  return hash.md5(secret).slice(0, 4);
}

function generateInitialisationVector() {
  return crypto.randomBytes(16);
}

function packMessage(message: EncryptedMessage) {
  return [
    message.secretDescriptor,
    message.initialisationVector.toString("base64"),
    message.cipher.toString("base64"),
  ].join(":");
}

function unpackMessage(message: string): EncryptedMessage {
  const [secretDescriptor, initialisationVector, cipher] = message.split(":");
  return {
    secretDescriptor,
    initialisationVector: Buffer.from(initialisationVector, "base64"),
    cipher: Buffer.from(cipher, "base64"),
  };
}

export class Encryptor {
  private readonly decryptionSecretsByDescriptor: Record<string, string> = {};

  constructor(
    private readonly encryptionSecret: string,
    decryptionSecrets: string[] = [encryptionSecret]
  ) {
    if (!isValidSecret(encryptionSecret)) {
      throw new Error(
        `\`encryptionSecret\` needs to be 32 characters, but was ${encryptionSecret.length} characters.`
      );
    }

    for (const s of decryptionSecrets) {
      if (!isValidSecret(s)) {
        throw new Error(
          `decryptionSecrets needs to be 32 characters, but was ${s.length} characters.`
        );
      }

      const id = getSecretDescriptor(s);
      this.decryptionSecretsByDescriptor[id] = s;
    }
  }

  public encrypt(input: string): string {
    const secretDescriptor = getSecretDescriptor(this.encryptionSecret);
    const iv = generateInitialisationVector();

    const cipher = crypto.createCipheriv(algo, this.encryptionSecret, iv);

    const encryptedInput = Buffer.concat([
      cipher.update(input, "utf8"),
      cipher.final(),
    ]);

    return packMessage({
      cipher: encryptedInput,
      initialisationVector: iv,
      secretDescriptor: secretDescriptor,
    });
  }

  public decrypt(string: string): string {
    const { cipher, initialisationVector, secretDescriptor } = unpackMessage(
      string
    );

    const key = this.decryptionSecretsByDescriptor[secretDescriptor];
    if (!key) {
      throw new Error("Could not decrypt: No matching secret.");
    }

    const decipher = crypto.createDecipheriv(algo, key, initialisationVector);

    return decipher.update(cipher, "hex", "utf8");
  }
}
