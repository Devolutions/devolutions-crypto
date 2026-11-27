# devolutions-crypto

This repo contains the library used for cryptography of products used by Devolutions. 
It also includes wrappers for it in different languages. The supported languages are: [Rust](src/), [C#](wrappers/csharp/), [Javascript/Typescript](wrappers/wasm/), [Kotlin](wrappers/kotlin), [Swift](wrappers/swift/), Python.
The Javascript version of the library is compiled using WebAssembly and can run in a browser.

devolutions-crypto uses the following algorithms.

 * Symmetric cryptography: XChaCha20Poly1305
 * Public-key cryptography: Curve25519
 * Asymmetric encryption: ECIES
 * Key exchange: x25519, ECDH over Curve25519
 * Key derivation: Argon2id, PBKDF2-HMAC-SHA2-256
 * Password Hashing: PBKDF2-HMAC-SHA2-256
 * Secret Sharing: Shamir Secret sharing over GF256
 * Online Ciphertext: XChaCha20-Poly1305

## License

This project is licensed under:
- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in devolutions-crypto by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Local development setup

### Rust

Build the project with cargo.

```
cargo build
cargo test
```

### C#

Build the rust library, then open the solution wrappers\csharp\tests\unit-tests\local\devolutions-crypto-tests\devolutions-crypto-tests.sln.

### WebAssembly

**Setup**

- Install the wasm32-unknown-unknown target with `rustup target add wasm32-unknown-unknown`
- Install `wasm-pack` with `cargo install wasm-pack`.

**Building**

Run `wasm_build.ps1` or `wasm_build.sh` in the wrappers/wasm folder.

Tests can then be run in the wrappers/wasm/tests folder.

```
npm install
npm run test
```

## The devolutions-crypto header

Data generated with devolutions-crypto is prefixed with a header that describes the cryptographic type
and its properties.

| Bytes     | Content                |
|-----------|------------------------|
|  1-2      | Signature Bytes (0xDC) |
|  3-4      | Data type              |
|  5-6      | Data sub type          |
|  7-8      | Version                |


### Data Type

| Data Types          | Value  |  Description                                                                 |
|---------------------|--------|------------------------------------------------------------------------------|
|  None               |  0x00  | No data type. Only used as a default value.                                  |
|  Key                |  0x10  | A wrapped key.                                                               |
|  Ciphertext         |  0x20  | A wrapped ciphertext. Can be either symmetric or asymmetric.                 |
|  PasswordHash       |  0x30  | A wrapped password hash. Used to verify a password.                          |
|  Share              |  0x40  | A wrapped share. Used for secret sharing scheme.                             |
|  SigningKey         |  0x50  | A wrapped key used to sign data.                                             |
|  Signature          |  0x60  | A wrapped signature.                                                         |
|  OnlineCiphertext   |  0x70  | A wrapped online ciphertext that can be encrypted/decrypted chunk by chunk   |
|  KeyDerivation      |  0x80  | Serialized key derivation parameters used to reproduce a derived secret key. |


### Sub types

| Key Sub Types | Value  |
|---------------|--------|
|  None         |  0x00  |
|  Private      |  0x10  |
|  Public       |  0x20  |
|  Pair         |  0x30  |
|  Secret       |  0x40  |

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


### Version
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

| Key Derivation Version | Value  | Description                                 |
|------------------------|--------|---------------------------------------------|
|  Latest                |  0x00  | Uses the latest version.                    |
|  V1                    |  0x10  | Uses version 1: PBKDF2-HMAC-SHA256.         |
|  V2                    |  0x20  | Uses version 2: Argon2id.                   |

| Online Ciphertext Version | Value  | Description                                                          |
|---------------------------|--------|----------------------------------------------------------------------|
|  Latest                   |  0x00  | Uses the latest version.                                             |
|  V1                       |  0x10  | Uses version 1: XChaCha20-Poly1305 wrapped in a STREAM construction. |


## Source of randomness

All randomness used by the library comes directly from the operating system's cryptographically secure random number generator (CSPRNG). The Rust core reads from the OS through the [`getrandom`](https://crates.io/crates/getrandom) crate. The wrappers (C#, Kotlin, Swift, Python, FFI) all call this Rust core. If the OS random source is unavailable, the library returns an error or panics. It never falls back to a weaker source.

The underlying source depends on the platform:

| Platform                | Source                                                     |
|-------------------------|------------------------------------------------------------|
| Linux, Android          | `getrandom(2)` system call (kernel CSPRNG)                 |
| Windows                 | `ProcessPrng` (CNG, the system CSPRNG)                     |
| macOS                   | `getentropy(2)`                                            |
| iOS                     | `CCRandomGenerateBytes` (CommonCrypto)                     |
| WebAssembly (browser)   | Web Crypto `crypto.getRandomValues`                        |
| WebAssembly (Node.js)   | Web Crypto `crypto.getRandomValues`                        |


