/*
The `BaseEncrypter` deals with the secure-e2ee-specific stuff.
The concrete encryption is offloaded to concrete versions,
which need to use aes-256-gcm, a symmetric encryption algorithm.

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

interface EncryptedMessage {
  secretDescriptor: string;
  cipher: Buffer;
  initialisationVector: Buffer;
}

function isValidSecret(string: String): boolean {
  return string.length === 32;
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

export abstract class BaseEncryptor {
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

      const id = this.getSecretDescriptor(s);
      this.decryptionSecretsByDescriptor[id] = s;
    }
  }

  protected abstract md5(input: string): string;

  public getSecretDescriptor(secret: string): string {
    return this.md5(secret).slice(0, 4);
  }

  protected abstract generateInitialisationVector(): Buffer;

  public async encrypt(input: string): Promise<string> {
    const secretDescriptor = this.getSecretDescriptor(this.encryptionSecret);
    const iv = this.generateInitialisationVector();

    const encryptedInput = await this._encrypt(
      input,
      iv,
      this.encryptionSecret
    );

    return packMessage({
      cipher: encryptedInput,
      initialisationVector: iv,
      secretDescriptor: secretDescriptor,
    });
  }

  protected abstract _encrypt(
    input: string,
    iv: Buffer,
    key: string
  ): Promise<Buffer>;

  public async decrypt(string: string): Promise<string> {
    const { cipher, initialisationVector, secretDescriptor } = unpackMessage(
      string
    );

    const key = this.decryptionSecretsByDescriptor[secretDescriptor];
    if (!key) {
      throw new Error("Could not decrypt: No matching secret.");
    }

    return await this._decrypt(cipher, initialisationVector, key);
  }

  protected abstract _decrypt(
    cipher: Buffer,
    iv: Buffer,
    key: string
  ): Promise<string>;
}
