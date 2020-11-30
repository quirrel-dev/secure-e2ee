import { BaseEncryptor } from "./base-encryptor";
import md5 from "md5";

export class BrowserEncryptor extends BaseEncryptor {
  protected md5(input: string): string {
    return md5(input);
  }
  protected generateInitialisationVector(): Buffer {
    throw new Error("Method not implemented.");
  }
  protected _encrypt(input: string, iv: Buffer, key: string): Promise<Buffer> {
    throw new Error("Method not implemented.");
  }
  protected _decrypt(cipher: Buffer, iv: Buffer, key: string): Promise<string> {
    throw new Error("Method not implemented.");
  }
}
