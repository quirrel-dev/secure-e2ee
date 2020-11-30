import { getSecretDescriptor } from "./base-encryptor";

describe("getSecretDescriptor", () => {
  it.each([
    ["abcde", "ab56"],
    ["dasda", "8f40"],
    ["e761daf732c272ee0db9bd71f49c66a0", "122e"],
  ])(`getSecretDescriptor("%s") == "%s"`, (input, output) => {
    expect(getSecretDescriptor(input)).toEqual(output);
  });
});