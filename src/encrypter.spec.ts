import { Encrypter } from "./encrypter";

describe("Encrypter", () => {
  describe(".secretToId", () => {
    it.each([
      ["abcde", "ab56"],
      ["dasda", "8f40"],
      ["e761daf732c272ee0db9bd71f49c66a0", "122e"],
    ])(`.secretToId("%s") == "%s"`, (input, output) => {
      expect(Encrypter.secretToId(input)).toEqual(output);
    });
  });

  describe("encryption flow", () => {
    describe("with one secret", () => {
      it("works", () => {
        const secret = "e761daf732c272ee0db9bd71f49c66a0";
        const input = "abcde";
        const iv = "dasdas";

        const encrypter = new Encrypter(secret, [secret], iv);

        const cipher_text = encrypter.encrypt(input);

        expect(cipher_text).toEqual("122e:3908201509");

        const deciphered_text = encrypter.decrypt(cipher_text);

        expect(deciphered_text).toEqual(input);
      });
    });

    describe("with secret rotation", () => {
      it("works", () => {
        const oldSecret = "e761daf732c272ee0db9bd71f49c66a0";
        const input = "abcde";

        const oldEncrypter = new Encrypter(oldSecret, [], iv);

        const cipher_text = oldEncrypter.encrypt(input);

        const newSecret = "ee0db9bd71f49c66a0e761daf732c272";

        const newEncrypter = new Encrypter(newSecret, [oldSecret], iv);

        const deciphered_text = newEncrypter.decrypt(cipher_text);

        expect(deciphered_text).toEqual(input);
      });
    });
  });
});
