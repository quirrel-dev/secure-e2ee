import { BaseEncryptor } from "./base-encryptor";
import md5 from "md5";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function concatUint8Array(a: Uint8Array, b: Uint8Array) {
  const result = new Uint8Array(a.byteLength + b.byteLength);
  result.set(new Uint8Array(a), 0);
  result.set(new Uint8Array(b), a.byteLength);
  return result;
}

async function getKey(key: string) {
  return await window.crypto.subtle.importKey(
    "raw",
    textEncoder.encode(key),
    {
      name: "AES-GCM",
    },
    false,
    ["encrypt", "decrypt"]
  );
}

export class BrowserEncryptor extends BaseEncryptor {
  protected md5(input: string): string {
    return md5(input);
  }

  generateInitialisationVector(): Uint8Array {
    return window.crypto.getRandomValues(new Uint8Array(16));
  }

  protected async _encrypt(
    input: string,
    iv: Uint8Array,
    key: string
  ): Promise<[Uint8Array, Uint8Array]> {
    const result = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128,
      },
      await getKey(key),
      textEncoder.encode(input)
    );

    const cipher = result.slice(0, result.byteLength - 16);
    const authTag = result.slice(result.byteLength - 16);

    return [new Uint8Array(cipher), new Uint8Array(authTag)];
  }
  protected async _decrypt(
    cipher: Uint8Array,
    authTag: Uint8Array | undefined,
    iv: Uint8Array,
    key: string
  ): Promise<string> {
    if (!authTag) {
      throw new Error("Could not decrypt: Auth tag missing.");
    }

    const result = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128,
      },
      await getKey(key),
      concatUint8Array(cipher, authTag)
    );

    return textDecoder.decode(result);
  }
}

export default BrowserEncryptor;
