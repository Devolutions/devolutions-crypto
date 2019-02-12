# DevolutionsCrypto
This repo contains the library used for cryptography of products used by Devolutions. 
It also includes wrapper for it for different languages.

## API Definition
### Provided Functions
It contains the following functions:  

`GenerateKey`: Generate a key of the required size using secure PRNGs.  
`DeriveKey`: Generates a key from a secret using the supplied parameters.  
`Encrypt`: Encrypt data with the provided key. Can take any size of key.  
`Decrypt`: Decrypt data with the provided key. Can take any size of key.  
`HashPassword`: Hash a password using high-cost algorithm so it is hard to brute-force. Depending on the wrapper,
you may need to specify an iteration number(the standard is 1000). Can also be used to derive a key. 
Should be use whenever there is a user provided password.  
`VerifyPassword`: Verify a password hash using constant time equality to prevent an array of side-channels attacks.  
`GenerateKeyExchange`: Generate a key pair to use in a Key Exchange. Should be used for any data in transit.  
MixKeyExchange: Mix a public key with a private key. Generates a shared secret between the client and the server.

### Technical Informations
As of the current version:

#### GenerateKey
Uses rand::OsRng which uses a platform-dependant cryptographically safe PRNG. 

#### DeriveKey
Uses PBKDF2 with HMAC-SHA256 to create a key using the supplied parameters.

#### Encrypt
1. Derives the secret using PBKDF2 into two keys using HMAC-SHA256 and 1 iteration: 
The encryption key(salt="\x00") and the signature key(salt="\x01").  
2. Generate a random 128bits Initialization Vector(IV).  
3. Encrypt the data using the encryption key and the IV.  
4. Create an HMAC-SHA256 of version + IV + encrypted_data using the signature key.  
5. Final: 4 version bytes + 16 IV bytes + data + 32 HMAC bytes.

#### HashPassword
1. Generate a random 256bits salt.  
2. Hash the password with the salt and the specified iteration number using HMAC-SHA256.  
3. Final: 4 version bytes + 4 bytes niterations + 32 bytes salt + 32 bytes hash

#### KeyExchange
The key exchanges uses x25519 protocol, which uses Diffie-Hellman based on elliptic curves.

## Wrappers and How To Build
Wrappers currently supported are for C# and WebAssembly. Since the C# bindings uses FFI, the same 
.dll should work for most languages bindings.

### C#

To build for release, you need to install rustup and add the required targets and then build for both of them.

#### Build the Library
##### Windows
Install the targets:
```batch
rustup add target x86_84-pc-windows-msvc
rustup add target i686-pc-windows-msvc
```
Then, navigate to `devolutionscrypto/` and run: 
```batch
cargo build --release --target x86_84-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```
##### Linux
Install the targets:
```bash
rustup add target x86_84-unknown-linux-gnu
rustup add target i686-unknown-linux-gnu
```
Then, navigate to `devolutionscrypto/` and run: 
```batch
cargo build --release --target x86_84-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

#### Import the Library
TODO

#### Use the Library
TODO

### WebAssembly
#### Build the Library
You need to install the `wasm32-unknown-unknown` toolchain:
```bash
rustup add target wasm32-unknown-unknown
```
You also need to install wasm-pack:
```bash
cargo install wasm-pack
```
Make sure your .cargo/bin is in your $PATH and run wasm_build.bat(on Windows) 
or wasm_build.sh(on Linux) to build the webassembly files.

#### Use the Library
Make sure your server returns the `application/wasm` Content-Type header on *.wasm requests.  
TODO
