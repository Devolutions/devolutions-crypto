[![Build Status](https://github.com/Devolutions/devolutions-crypto/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Devolutions/devolutions-crypto/actions/workflows/ci.yml)

[![crates.io](https://img.shields.io/crates/v/devolutions-crypto.svg)](https://crates.io/crates/devolutions-crypto) 
[![npmjs](https://img.shields.io/npm/v/%40devolutions%2Fdevolutions-crypto)](https://www.npmjs.com/package/@devolutions/devolutions-crypto)
[![pypi](https://img.shields.io/pypi/v/devolutions-crypto)](https://pypi.org/project/devolutions-crypto/)
[![kotlin](https://img.shields.io/badge/kotlin-2025.2.12-orange)](https://cloudsmith.io/~devolutions/repos/maven-public/packages/detail/maven/devolutions-crypto/2025.2.12/a=noarch;xg=devolutions/)
[![swift](https://img.shields.io/badge/swift-2025.2.12-orange)](https://github.com/Devolutions/devolutions-crypto/tree/2601b67f8347bdcf2ae4f2505e9a34940d85a3f9)




# DevolutionsCrypto
This repo contains the library used for cryptography of products used by Devolutions. 
It also includes wrappers for it in different languages.  
Currently, the supported languages are: [Rust](src/), [C#](wrappers/csharp/) and [Javascript/Typescript](wrappers/wasm/), [Kotlin](wrappers/kotlin), [Swift](wrappers/swift/)

Python bindings are also available. You can install it with `pip3 install devolutions-crypto`, but this might not work depending on the platform. If it doesn't, you can try building it manually.

Note that the Javascript version of the library is compiled using WebAssembly, so it can run in a browser.

# Underlying algorithms
As of the current version:
 * Symmetric cryptography uses XChaCha20Poly1305
 * Asymmetric cryptography uses Curve25519.
 * Asymmetric encryption uses ECIES.
 * Key exchange uses x25519, or ECDH over Curve25519
 * Password Hashing uses PBKDF2-HMAC-SHA2-256
 * Secret Sharing uses Shamir Secret sharing over GF256
 * Online Ciphertext uses XChaCha20-Poly1305

# License

This project is licensed under either of
- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in devolutions-crypto by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.



# Devolutions Crypto Header

### Example Header 
| Position  | Byte value  |
|-----------|-------------|
|  1        |       0xD   |
|  2        |       0xC   |
|  3        |       0x1   |
|  4        |       0x0   |
|  5        |       0x1   |
|  6        |       0x0   |
|  7        |       0x1   |
|  8        |       0x0   |

This header represents : 
A Curve25519 private key from Devolutions Crypto


- Signature Bytes
  -  The first two bytes specifies that the data is from Devolutions Crypto (DC) 
- Data type
  - The second two bytes (pos: 3,4 ) represents the data type.
- Data sub type
  - The third two bytes (pos: 5, 6) represents the data sub type.
- Version
  - The fourth two bytes (pos: 7, 8) represents the version.

## Data Type
| Data Types          | Value  |  Description                                                                 |
|---------------------|--------|------------------------------------------------------------------------------|
|  None               |  0x00  | No data type. Only used as a default value.                                  |
|  Key                |  0x10  | A wrapped key.                                                               |
|  Ciphertext         |  0x20  | A wrapped ciphertext. Can be either symmetric or asymmetric.                 |
|  PasswordHash       |  0x30  | A wrapped password hash. Used to verify a password.                          |
|  Share              |  0x40  | A wrapped share. Used for secret sharing scheme.                             |
|  SigningKey         |  0x50  | A wrapped key used to sign data.                                             |
|  Signature          |  0x60  | A wrapped signature.                                                         |
|  OnlineCiphertext   |  0x70  | A wrapped online ciphertext that can be encrypted/decrypted chunk by chunk  |



## Sub types

| Key Sub Types | Value  |
|---------------|--------|
|  None         |  0x00  |
|  Private      |  0x10  |
|  Public       |  0x20  |
|  Pair         |  0x30  |

| Ciphertext Sub Types | Value  |
|----------------------|--------|
|  None                |  0x00  |
|  Symmetric           |  0x10  |
|  Asymmetric          |  0x20  |

| PasswordHash Sub Types | Value  |
|------------------------|--------|
|  None                  |  0x00  |

| Share Sub Types | Value  |
|-----------------|--------|
|  None           |  0x00  |

| Signature Sub Types | Value  |
|---------------------|--------|
|  None               |  0x00  |


## Version
| Key Version          | Value  | Description                                                 |
|----------------------|--------|-------------------------------------------------------------|
|  Latest              |  0x00  | Uses the latest version.                                    |
|  V1                  |  0x10  | Uses version 1: Curve25519 keys and x25519 key exchange.    |

| Ciphertext Version | Value  | Description                               |
|--------------------|--------|-------------------------------------------|
|  Latest            |  0x00  | Uses the latest version.                  |
|  V1                |  0x10  | Uses version 1: AES256-CBC-HMAC-SHA2-256. |
|  V2                |  0x20  | Uses version 2: XChaCha20-Poly1305.       |

| PasswordHash Version | Value  | Description                               |
|----------------------|--------|-------------------------------------------|
|  Latest              |  0x00  | Uses the latest version.                  |
|  V1                  |  0x10  | Uses version 1: PBKDF2-HMAC-SHA2-256.     |

| Secret Sharing Version | Value  | Description                                       |
|------------------------|--------|---------------------------------------------------|
|  Latest                |  0x00  | Uses the latest version.                          |
|  V1                    |  0x10  | Uses version 1: Shamir Secret Sharing over GF256. |

| Signing Key Version | Value  | Description              |
|---------------------|--------|--------------------------|
|  Latest             |  0x00  | Uses the latest version. |
|  V1                 |  0x10  | Uses version 1: Ed25519. |

| Signature Version | Value  | Description              |
|-------------------|--------|--------------------------|
|  Latest           |  0x00  | Uses the latest version. |
|  V1               |  0x10  | Uses version 1: ed25519. |

| Online Ciphertext Version | Value  | Description                                                          |
|---------------------------|--------|----------------------------------------------------------------------|
|  Latest                   |  0x00  | Uses the latest version.                                             |
|  V1                       |  0x10  | Uses version 1: XChaCha20-Poly1305 wrapped in a STREAM construction. |


