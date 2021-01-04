import { BaseEncryptor } from "./base-encryptor";
import md5 from "md5";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

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
  ): Promise<Uint8Array> {
    const result = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
      },
      await getKey(key),
      textEncoder.encode(input)
    );

    return new Uint8Array(result);
  }
  protected async _decrypt(
    cipher: Uint8Array,
    iv: Uint8Array,
    key: string
  ): Promise<string> {
    const result = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
      },
      await getKey(key),
      cipher
    );

    return textDecoder.decode(result);
  }
}

export default BrowserEncryptor;
