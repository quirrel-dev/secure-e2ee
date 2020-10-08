import { Encryptor, getSecretDescriptor } from "./encryptor";

describe("Encryptor", () => {
  describe("getSecretDescriptor", () => {
    it.each([
      ["abcde", "ab56"],
      ["dasda", "8f40"],
      ["e761daf732c272ee0db9bd71f49c66a0", "122e"],
    ])(`getSecretDescriptor("%s") == "%s"`, (input, output) => {
      expect(getSecretDescriptor(input)).toEqual(output);
    });
  });

  describe("when given an invalid secret", () => {
    it("throws", () => {
      expect(() => new Encryptor("too-short")).toThrowError(
        "`encryptionSecret` needs to be 32 characters, but was 9 characters."
      );

      expect(
        () => new Encryptor("e761daf732c272ee0db9bd71f49c66a0", ["too-short"])
      ).toThrowError(
        "decryptionSecrets needs to be 32 characters, but was 9 characters."
      );
    });
  });

  describe("encryption flow", () => {
    describe("with one secret", () => {
      it("works", () => {
        const secret = "e761daf732c272ee0db9bd71f49c66a0";
        const input = "abcde";

        const encryptor = new Encryptor(secret);

        const ciphered_message = encryptor.encrypt(input);

        const deciphered_text = encryptor.decrypt(ciphered_message);

        expect(deciphered_text).toEqual(input);
      });
    });

    describe("with secret rotation", () => {
      it("works", () => {
        const oldSecret = "e761daf732c272ee0db9bd71f49c66a0";
        const input = "abcde";

        const oldEncryptor = new Encryptor(oldSecret);

        const cipher_text = oldEncryptor.encrypt(input);

        const newSecret = "ee0db9bd71f49c66a0e761daf732c272";

        const newEncryptor = new Encryptor(newSecret, [oldSecret]);

        const deciphered_text = newEncryptor.decrypt(cipher_text);

        expect(deciphered_text).toEqual(input);
      });

      describe("and used secret not existing", () => {
        it("throws an error", () => {
          const oldSecret = "e761daf732c272ee0db9bd71f49c66a0";
          const input = "abcde";

          const oldEncryptor = new Encryptor(oldSecret);

          const cipher_text = oldEncryptor.encrypt(input);

          const newSecret = "ee0db9bd71f49c66a0e761daf732c272";

          const newEncryptor = new Encryptor(newSecret);

          expect(() => {
            newEncryptor.decrypt(cipher_text);
          }).toThrowError("Could not decrypt: No matching secret.");
        });
      });
    });
  });
});
