import { Encrypter } from "./encrypter";

describe("Encrypter", () => {
  describe(".getSecretDescriptor", () => {
    it.each([
      ["abcde", "ab56"],
      ["dasda", "8f40"],
      ["e761daf732c272ee0db9bd71f49c66a0", "122e"],
    ])(`.getSecretDescriptor("%s") == "%s"`, (input, output) => {
      expect(Encrypter.getSecretDescriptor(input)).toEqual(output);
    });
  });

  describe("encryption flow", () => {
    describe("with one secret", () => {
      it("works", () => {
        const secret = "e761daf732c272ee0db9bd71f49c66a0";
        const input = "abcde";

        const encrypter = new Encrypter(secret);

        const ciphered_message = encrypter.encrypt(input);

        const deciphered_text = encrypter.decrypt(ciphered_message);

        expect(deciphered_text).toEqual(input);
      });
    });

    describe("with secret rotation", () => {
      it("works", () => {
        const oldSecret = "e761daf732c272ee0db9bd71f49c66a0";
        const input = "abcde";

        const oldEncrypter = new Encrypter(oldSecret);

        const cipher_text = oldEncrypter.encrypt(input);

        const newSecret = "ee0db9bd71f49c66a0e761daf732c272";

        const newEncrypter = new Encrypter(newSecret, [oldSecret]);

        const deciphered_text = newEncrypter.decrypt(cipher_text);

        expect(deciphered_text).toEqual(input);
      });

      describe("and used secret not existing", () => {
        it("throws an error", () => {
          const oldSecret = "e761daf732c272ee0db9bd71f49c66a0";
        const input = "abcde";

        const oldEncrypter = new Encrypter(oldSecret);

        const cipher_text = oldEncrypter.encrypt(input);

        const newSecret = "ee0db9bd71f49c66a0e761daf732c272";

        const newEncrypter = new Encrypter(newSecret);

        expect(() => {
          newEncrypter.decrypt(cipher_text);
        }).toThrowError("Could not decrypt: No matching secret.");
        })
      })
    });
  });
});
