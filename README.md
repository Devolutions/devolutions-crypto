[![Build Status](https://dev.azure.com/devolutions-net/Open%20Source/_apis/build/status/devolutions-crypto?branchName=master)](https://dev.azure.com/devolutions-net/Open%20Source/_build/latest?definitionId=170&branchName=master) [![](https://meritbadge.herokuapp.com/devolutions-crypto)](https://crates.io/crates/devolutions-crypto) [![npm version](https://img.shields.io/npm/v/devolutions-crypto.svg?style=flat)](https://npmjs.org/package/devolutions-crypto "View this project on npm")

# DevolutionsCrypto
This repo contains the library used for cryptography of products used by Devolutions. 
It also includes wrappers for it in different languages.  
Currently, the supported languages are: [Rust](devolutions-crypto/), [C#](wrappers/csharp/) and [Javascript/Typescript](wrappers/wasm/).

Note that the Javascript version of the library is compiled using WebAssembly, so it can run in a browser.

# Underlying algorithms
As of the current version:
 * Symmetric cryptography uses XChaCha20Poly1305
 * Asymmetric cryptography uses Curve25519.
 * Asymmetric encryption uses ECIES.
 * Key exchange uses x25519, or ECDH over Curve25519
 * Password Hashing uses PBKDF2-HMAC-SHA2-256
 * Secret Sharing uses Shamir Secret sharing over GF256

# License

This project is licensed under either of
- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in devolutions-crypto by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
