import type { Encryptor as EncryptorClass } from "./encryptor";
import { expect } from "chai";

export function testEncryptor(_Encryptor: any) {
  const Encryptor = _Encryptor as typeof EncryptorClass;

  describe(Encryptor.name, () => {
    describe("getSecretDescriptor", () => {
      const encryptor = new Encryptor("e761daf732c272ee0db9bd71f49c66a0");

      [
        ["abcde", "ab56"],
        ["dasda", "8f40"],
        ["e761daf732c272ee0db9bd71f49c66a0", "122e"],
      ].forEach(([input, output]) => {
        it(`getSecretDescriptor("${input}") == "${output}"`, () => {
          expect(encryptor.getSecretDescriptor(input)).to.equal(output);
        });
      });
    });

    it("generateInitialisationVecotr", () => {
      expect(
        new Encryptor(
          "e761daf732c272ee0db9bd71f49c66a0"
        ).generateInitialisationVector()
      ).to.have.length(16);
    });

    describe("when given an invalid secret", () => {
      it("throws", () => {
        expect(() => new Encryptor("too-short")).to.throw(
          "`encryptionSecret` needs to be 32 characters, but was 9 characters."
        );

        expect(
          () => new Encryptor("e761daf732c272ee0db9bd71f49c66a0", ["too-short"])
        ).to.throw(
          "decryptionSecrets needs to be 32 characters, but was 9 characters."
        );
      });
    });

    describe("encryption flow", () => {
      it("when encrypting on one and decrypting on the other", async () => {
        const secret = "e761daf732c272ee0db9bd71f49c66a0";

        const encryptor = new Encryptor(secret);

        let callsToIv = 0;
        encryptor.generateInitialisationVector = () => {
          callsToIv++;
          return Buffer.from(
            Uint8Array.from([
              74,
              239,
              191,
              189,
              239,
              191,
              189,
              220,
              153,
              65,
              83,
              101,
              45,
              44,
              33,
              110,
              239,
              191,
              189,
              239,
              191,
              189,
              239,
              191,
              189,
              239,
              191,
              189,
            ])
          );
        };

        const input = "abcde";

        const ciphered_message = await encryptor.encrypt(input);

        expect(ciphered_message).to.eq(
          "122e:Su+/ve+/vdyZQVNlLSwhbu+/ve+/ve+/ve+/vQ==:0MjARaXgGQPbyWCphrEEdAvhJa9n"
        );

        const deciphered_text = await encryptor.decrypt(ciphered_message);
        expect(deciphered_text).to.equal(input);

        expect(callsToIv).to.eq(1);
      });

      describe("with one secret", () => {
        it("works", async () => {
          const secret = "e761daf732c272ee0db9bd71f49c66a0";
          const input = "abcde";

          const encryptor = new Encryptor(secret);

          const ciphered_message = await encryptor.encrypt(input);

          const deciphered_text = await encryptor.decrypt(ciphered_message);

          expect(deciphered_text).to.equal(input);
        });
      });

      describe("with very small input", () => {
        it("works", async () => {
          const secret = "e761daf732c272ee0db9bd71f49c66a0";
          const input = JSON.stringify(null);

          const encryptor = new Encryptor(secret);

          const ciphered_message = await encryptor.encrypt(input);

          const deciphered_text = await encryptor.decrypt(ciphered_message);

          expect(JSON.parse(deciphered_text)).to.be.null;
        });
      });

      describe("with secret rotation", () => {
        it("works", async () => {
          const oldSecret = "e761daf732c272ee0db9bd71f49c66a0";
          const input = "abcde";

          const oldEncryptor = new Encryptor(oldSecret);

          const cipher_text = await oldEncryptor.encrypt(input);

          const newSecret = "ee0db9bd71f49c66a0e761daf732c272";

          const newEncryptor = new Encryptor(newSecret, [oldSecret]);

          const deciphered_text = await newEncryptor.decrypt(cipher_text);

          expect(deciphered_text).to.equal(input);
        });

        describe("and used secret not existing", () => {
          it("throws an error", async () => {
            const oldSecret = "e761daf732c272ee0db9bd71f49c66a0";
            const input = "abcde";

            const oldEncryptor = new Encryptor(oldSecret);

            const cipher_text = await oldEncryptor.encrypt(input);

            const newSecret = "ee0db9bd71f49c66a0e761daf732c272";

            const newEncryptor = new Encryptor(newSecret);

            try {
              await newEncryptor.decrypt(cipher_text);
            } catch (error) {
              expect(error).to.be.instanceOf(Error);
              expect(error.message).to.equal(
                "Could not decrypt: No matching secret."
              );
            }
          });
        });
      });
    });
  });
}
