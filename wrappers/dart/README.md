# Devolutions Crypto - Dart Bindings

Dart bindings for [Devolutions Crypto](https://github.com/devolutions/devolutions-crypto), a cryptographic library providing encryption, password hashing, secret sharing, and digital signatures.

These bindings are generated using [uniffi-dart](https://github.com/Uniffi-Dart/uniffi-dart), a Dart frontend for Mozilla's UniFFI framework.

## Features

- **Symmetric Encryption**: ChaCha20-Poly1305 and AES encryption with optional Additional Authenticated Data (AAD)
- **Asymmetric Encryption**: X25519-based public key encryption
- **Password Hashing**: PBKDF2, Argon2, and other secure password derivation functions
- **Secret Sharing**: Shamir's Secret Sharing implementation
- **Digital Signatures**: Ed25519 signing and verification
- **Key Generation**: Secure key pair generation for encryption and signing

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| Windows  | x64         | ✅ Supported |
| Linux    | x64         | ✅ Supported |
| macOS    | x64, ARM64  | ✅ Supported |
| Android  | arm64-v8a, armeabi-v7a, x86, x86_64 | ✅ Supported |
| iOS      | arm64, Simulator | ✅ Supported |

## Installation

### For Package Users

Once published to pub.dev, add this to your `pubspec.yaml`:

```yaml
dependencies:
  devolutions_crypto: ^0.9.3
```

Then run:

```bash
dart pub get
```

### For Contributors / Building from Source

If you want to build the package from source or contribute:

#### Prerequisites

1. **Rust toolchain**: Install from [rustup.rs](https://rustup.rs/)
2. **Dart SDK**: Version 3.0.0 or higher
3. **uniffi-dart**: Clone and build the uniffi-dart project

#### Step 1: Clone uniffi-dart

```bash
git clone https://github.com/Uniffi-Dart/uniffi-dart.git
cd uniffi-dart
cargo build --release
cd ..
```

#### Step 2: Set Environment Variable

```bash
export UNIFFI_DART_DIR=/path/to/uniffi-dart
```

Add this to your `~/.bashrc`, `~/.zshrc`, or equivalent for persistence.

#### Step 3: Navigate to the Dart Wrapper

```bash
cd wrappers/dart
```

#### Step 4: Generate Dart Bindings

```bash
./generate.sh
```

This script will:
1. Build the Rust library (`devolutions-crypto-uniffi`)
2. Generate Dart bindings using uniffi-dart
3. Install Dart dependencies
4. Format the generated code

#### Step 5: Build Native Libraries (Optional)

To build native libraries for specific platforms:

```bash
# For your current platform
make linux    # or: make windows, make macos, make android, make ios

# For all platforms
make all-platforms
```

See the [Makefile](Makefile) for all available targets.

## Usage

### Basic Example

```dart
import 'package:devolutions_crypto/devolutions_crypto.dart';
import 'dart:convert';
import 'dart:typed_data';

void main() {
  // Generate a key pair for asymmetric encryption
  final keyPair = generateKeypair();
  print('Generated key pair');
  print('Public key: ${keyPair.publicKey.length} bytes');
  print('Private key: ${keyPair.privateKey.length} bytes');

  // Symmetric encryption
  final data = utf8.encode('Hello, Devolutions Crypto!');
  final key = Uint8List.fromList(List<int>.generate(32, (i) => i));
  final encrypted = encrypt(data, key);
  print('Encrypted ${data.length} bytes -> ${encrypted.length} bytes');

  // Password hashing
  final password = utf8.encode('mySecurePassword123');
  final hash = hashPassword(password, iterations: 10000);
  print('Password hash: ${hash.length} bytes');

  // Secret sharing (5 shares, 3 required to reconstruct)
  final shares = generateSharedKey(5, 3, length: 32);
  print('Generated ${shares.length} shares');

  // Digital signatures
  final signingKeyPair = generateSigningKeypair();
  final dataToSign = utf8.encode('Document to sign');
  final signature = sign(
    dataToSign,
    Uint8List.fromList([
      ...signingKeyPair.getPublicKey(),
      ...signingKeyPair.getPrivateKey(),
    ]),
  );
  print('Signature: ${signature.length} bytes');
}
```

### More Examples

See the [example](example/) directory for more comprehensive examples:

```bash
dart run example/devolutions_crypto_example.dart
```

## API Reference

### Encryption

- `encrypt(data, key, [version])` - Symmetric encryption
- `encryptWithAad(data, key, aad, [version])` - Encryption with AAD
- `encryptAsymmetric(data, publicKey, [version])` - Asymmetric encryption
- `encryptAsymmetricWithAad(data, publicKey, aad, [version])` - Asymmetric with AAD

### Key Generation

- `generateKeypair([version])` - Generate encryption key pair
- `generateSigningKeypair([version])` - Generate signing key pair

### Password Hashing

- `hashPassword(password, [iterations], [version])` - Hash a password

### Secret Sharing

- `generateSharedKey(nShares, threshold, [length], [version])` - Generate shared secret

### Digital Signatures

- `sign(data, keypair, [version])` - Sign data

### Data Types

- `KeyPair` - Encryption key pair (publicKey, privateKey)
- `SigningKeyPair` - Signing key pair
- `DevolutionsCryptoError` - Error enum
- `CiphertextVersion`, `KeyVersion`, `PasswordHashVersion`, etc. - Version enums

## Development

### Running Tests

```bash
# Run all tests
dart test

# Run tests with coverage
dart test --coverage
```

### Code Quality

```bash
# Analyze code
dart analyze

# Format code
dart format lib/ test/ example/

# Check for issues before publishing
dart pub publish --dry-run
```

### Building for Multiple Platforms

The [Makefile](Makefile) provides targets for building native libraries:

```bash
make help        # Show all available commands
make bindings    # Regenerate Dart bindings
make windows     # Build for Windows
make linux       # Build for Linux
make macos       # Build for macOS
make android     # Build for Android
make ios         # Build for iOS
make clean       # Clean build artifacts
```

## Project Structure

```
wrappers/dart/
├── lib/
│   ├── devolutions_crypto.dart       # Main library export
│   ├── src/
│   │   ├── loader.dart               # Native library loader
│   │   └── generated/                # Generated UniFFI bindings (git ignored)
│   └── native/                       # Native libraries (git ignored)
│       ├── windows-x64/
│       ├── linux-x64/
│       ├── macos-arm64/
│       ├── android-*/
│       └── ios-*/
├── example/
│   └── devolutions_crypto_example.dart
├── test/
│   └── devolutions_crypto_test.dart
├── pubspec.yaml                      # Package metadata
├── generate.sh                       # Binding generation script
├── Makefile                          # Build automation
├── README.md                         # This file
├── CHANGELOG.md                      # Version history
└── LICENSE                           # License file
```

## Known Limitations

### uniffi-dart Feature Support

As uniffi-dart is still in development, some UniFFI features may have limitations:

- HashMap/Map support
- Procedural macro support
- Dictionary default values
- Trait methods
- BigInt for large integers

See the [uniffi-dart repository](https://github.com/Uniffi-Dart/uniffi-dart) for the latest status.

### Native Library Loading (⚠️ Blocked by Dart Native Assets Evolution)

The generated bindings use **Dart's native assets system** which is currently under active development.

**Status:**
- ✅ Bindings generate successfully (2362 lines)
- ✅ Code compiles without errors
- ✅ Native libraries build successfully
- ⚠️ Runtime execution blocked by unstable native assets API

**Why:** Dart's native assets API is in flux (`native_assets_cli` discontinued, `hooks` package not yet stable). uniffi-dart and this package are ready but waiting for the Dart ecosystem to stabilize.

**Solutions:** Wait for native assets to stabilize, OR fork uniffi-dart to use traditional `DynamicLibrary.open()`. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for details.

## Contributing

Contributions are welcome! Please see the main [Devolutions Crypto repository](https://github.com/devolutions/devolutions-crypto) for contribution guidelines.

### Reporting Issues

Please report issues on the [GitHub issue tracker](https://github.com/devolutions/devolutions-crypto/issues).

## License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](../../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Related Projects

- [Devolutions Crypto (Rust)](https://github.com/devolutions/devolutions-crypto) - Main Rust library
- [uniffi-dart](https://github.com/Uniffi-Dart/uniffi-dart) - Dart frontend for UniFFI
- [UniFFI](https://mozilla.github.io/uniffi-rs/) - Mozilla's multi-language bindings generator

## Resources

- [Documentation](https://github.com/devolutions/devolutions-crypto/tree/master/wrappers/dart)
- [Examples](./example/)
- [Changelog](./CHANGELOG.md)
- [pub.dev page](https://pub.dev/packages/devolutions_crypto) (once published)
