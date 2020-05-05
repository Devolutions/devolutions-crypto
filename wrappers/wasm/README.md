# devolutions-crypto
[![Build Status](https://dev.azure.com/devolutions-net/Open%20Source/_apis/build/status/devolutions-crypto?branchName=master)](https://dev.azure.com/devolutions-net/Open%20Source/_build/latest?definitionId=170&branchName=master) [![npm version](https://img.shields.io/npm/v/devolutions-crypto.svg?style=flat)](https://npmjs.org/package/devolutions-crypto "View this project on npm")

Cryptographic library used in Devolutions products. It is made to be fast, easy to use and misuse-resistant.

# Usage
You can refer to the [Angular example](example/) or the [unit tests](tests/) to see how to use the library.

# Underlying algorithms
As of the current version:
 * Symmetric cryptography uses XChaCha20Poly1305
 * Asymmetric cryptography uses Curve25519.
 * Asymmetric encryption uses ECIES.
 * Key exchange uses x25519, or ECDH over Curve25519
 * Password Hashing uses PBKDF2-HMAC-SHA2-256
 * Secret Sharing uses Shamir Secret sharing over GF256

# Known Issue
You will also need to import the library asynchronously(using `import().then()`). This is a browser limitation that prohibits loading WebAssembly in the main chunk. To see how to do it cleanly, please refer to the [Angular example](example/).

On firefox, exception shows up as `Error` in the console if not caught, but the value of `error.name` is the right one, so you can still try/catch depending on the error name.  

# Building devolutions-crypto for ie / browser without WebASM support
First of all you will need to download wasm2js binary according to your platform : [Download from GitHub](https://github.com/WebAssembly/binaryen/releases)
 * Add wasm2js to your path.
 * Make sure you are at `<path_to_devolutions_crypto>/wrappers/wasm/`
 * Make sure your build directory if clean by running `rm -rf dist/`
 * run `./ie_build.sh`

If you need devolutions-crypto to be compatible with a specific browser version, add it to the [browserslist](./browserslist) file.
