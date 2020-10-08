# secure-e2ee

Secure end-to-end-encryption for Node.js.

## Usage

```ts
import Encryptor from "secure-e2ee";

const encryptor = new Encryptor(
    // encryption secret
    // needs to be 32 characters long
    "e761daf732c272ee0db9bd71f49c66a0",

    // old encryption secrets
    // that have been rotated out.
    // (optional)
    [
        "e761daf732c272ee0db9bd71f49c66a0",
        "c272732c66aee0db9bd71f49e761daf0",
    ]
);

const cipher = encryptor.encrypt("I ❤️ Blitz.js");

// send over the wire

const original = encryptor.decrypt(cipher);

// original === "I ❤️ Blitz.js";
```