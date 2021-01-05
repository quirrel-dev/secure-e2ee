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

import b64 from "base64-js";

interface EncryptedMessage {
  secretDescriptor: string;
  cipher: Uint8Array;
  initialisationVector: Uint8Array;
  authTag?: Uint8Array;
}

function isValidSecret(string: String): boolean {
  return string.length === 32;
}

function packMessage(message: EncryptedMessage) {
  const arr = [
    message.secretDescriptor,
    b64.fromByteArray(message.initialisationVector),
    b64.fromByteArray(message.cipher),
  ];

  if (message.authTag) {
    arr.push(b64.fromByteArray(message.authTag));
  }

  return arr.join(":");
}

function unpackMessage(message: string): EncryptedMessage {
  const [
    secretDescriptor,
    initialisationVector,
    cipher,
    authTag,
  ] = message.split(":");
  return {
    secretDescriptor,
    initialisationVector: b64.toByteArray(initialisationVector),
    cipher: b64.toByteArray(cipher),
    authTag: authTag ? b64.toByteArray(authTag) : undefined,
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

  abstract generateInitialisationVector(): Uint8Array;

  public async encrypt(input: string): Promise<string> {
    const secretDescriptor = this.getSecretDescriptor(this.encryptionSecret);
    const initialisationVector = this.generateInitialisationVector();

    const [cipher, authTag] = await this._encrypt(
      input,
      initialisationVector,
      this.encryptionSecret
    );

    return packMessage({
      cipher,
      authTag,
      initialisationVector,
      secretDescriptor,
    });
  }

  protected abstract _encrypt(
    input: string,
    iv: Uint8Array,
    key: string
  ): Promise<[cipher: Uint8Array, authTag: Uint8Array]>;

  public async decrypt(string: string): Promise<string> {
    const {
      cipher,
      initialisationVector,
      secretDescriptor,
      authTag,
    } = unpackMessage(string);

    const key = this.decryptionSecretsByDescriptor[secretDescriptor];
    if (!key) {
      throw new Error("Could not decrypt: No matching secret.");
    }

    return await this._decrypt(cipher, authTag, initialisationVector, key);
  }

  protected abstract _decrypt(
    cipher: Uint8Array,
    authTag: Uint8Array | undefined,
    iv: Uint8Array,
    key: string
  ): Promise<string>;
}
