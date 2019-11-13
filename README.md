[![Build Status](https://dev.azure.com/mrmathmo/DevolutionsCrypto/_apis/build/status/Devolutions.devolutions-crypto?branchName=master)](https://dev.azure.com/mrmathmo/DevolutionsCrypto/_build/latest?definitionId=2&branchName=master)

# DevolutionsCrypto
This repo contains the library used for cryptography of products used by Devolutions. 
It also includes wrapper for it for different languages.  
Currently, the C# wrapper is supported for the implemented methods. Webassembly build and works,
but is still considered alpha and not production-ready.   
The minimum Rust version to build on stable is 1.34.


## API Definition
### Provided Functions
It contains the following functions:  

`GenerateKey`: Generate a key of the required size using secure PRNGs.  
`DeriveKey`: Generates a key from a secret using the supplied parameters.  
`Encrypt`: Encrypt data with the provided key. Can take any size of key, but if it is a password you should use DeriveKey before.  
`Decrypt`: Decrypt data with the provided key. Can take any size of key, but if it is a password you should use DeriveKey before.  
`HashPassword`: Hash a password using high-cost algorithm so it is hard to brute-force. Depending on the wrapper,
you may need to specify an iteration number(the standard is 10000). Can also be used to derive a key. 
Should be used whenever there is a user provided password.  
`VerifyPassword`: Verify a password hash using constant time equality to prevent an array of side-channels attacks.  
`GenerateKeyExchange`: Generate a key pair to use in a Key Exchange. Should be used for any data in transit.  
`MixKeyExchange`: Mix a public key with a private key. Generates a shared secret between the client and the server.

### Technical Informations
As of the current version:

#### GenerateKey
Uses rand::OsRng which uses a platform-dependant cryptographically safe PRNG. 

#### DeriveKey
Uses PBKDF2 with HMAC-SHA256 to create a key using the supplied parameters.

#### Encrypt
1. Derives the secret into a key using SHA256.  
2. Generate a random 192bits nonce.  
3. Encrypt the data using the encryption key and the nonce with the XChaCha20Poly1305 AEAD. The header is used as the associated data so it is authenticated and can't be tampered.  
5. Final: 8 header bytes + 24 nonce bytes + data + 16 authentication tag bytes.

#### HashPassword
1. Generate a random 256bits salt.  
2. Hash the password with the salt and the specified iteration number using PBKDF2-HMAC-SHA256.  
3. Final: 8 header bytes + 4 bytes iterations + 32 bytes salt + 32 bytes hash

#### KeyExchange
The key exchanges uses x25519 protocol, which uses Diffie-Hellman based on elliptic curves.

## Headers
The current data header works as the following:  
1. 2 bytes signature: [ 0x0D, 0x0C ], stands for Devolutions Crypto.  
2. 2 bytes type in Little Endian. The following types are implemented:  
    - Key = 1
    - Ciphertext = 2
    - Hash = 3
3. 2 bytes subtype in little endian.
    - Key
        - Private = 1
        - Public = 2
4. 2 bytes version in Little Endian. Currently, everything is at version 1.

## Wrappers and How To Build
Wrappers currently supported are for C# and WebAssembly. Since the C# bindings uses FFI, the same 
.dll should work for most languages bindings.

### C#

To build for release, you need to install rustup and add the required targets and then build for both of them.

#### Build the Library
##### Windows
Install the targets:
```batch
rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc
```

Then, navigate to `devolutionscrypto/` and run: 
```batch
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```
##### Linux
Install the targets:
```bash
rustup target add x86_64-unknown-linux-gnu
rustup target add i686-unknown-linux-gnu
```
Then, navigate to `devolutionscrypto/` and run: 
```batch
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```
##### MacOS
Install the targets:
```bash
rustup target add x86_64-apple-darwin
rustup target add i686-apple-darwin
```
Then, navigate to `devolutionscrypto/` and run: 
```batch
cargo build --release --target x86_64-apple-darwin
cargo build --release --target i686-apple-darwin
```
##### Android
You can refer to the following link on how to setup rust for android:  
https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html  
Install the targets:
```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android
```
Then, navigate to `devolutionscrypto/` and run: 
```batch
cargo build --release --target aarch64-linux-android
cargo build --release --target armv7-linux-androideabi
cargo build --release --target i686-linux-android
```
##### iOS
You can refer to the following link on how to setup rust for android:  
https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-06-rust-on-ios.html  
Install the targets:
```bash
rustup target add aarch64-apple-ios
rustup target add armv7-apple-ios
rustup target add armv7s-apple-ios
rustup target add x86_64-apple-ios
rustup target add i386-apple-ios
```
Then, navigate to `devolutionscrypto/` and run: 
```batch
cargo build --release --target aarch64-apple-ios
cargo build --release --target armv7-apple-ios
cargo build --release --target armv7s-apple-ios
cargo build --release --target x86_64-apple-ios
cargo build --release --target i386-apple-ios
```

#### Import the Library
TODO

#### Use the Library
View the examples.md file in the wrappers folder

### WebAssembly
Refer to the `wrappers/wasm/README.md` file info regarding webassembly.

# License

This project is licensed under either of
- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in devolutions-crypto by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.