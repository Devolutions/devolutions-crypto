/// Dart bindings for Devolutions Crypto
///
/// A cryptographic library providing encryption, password hashing,
/// secret sharing, and digital signatures. Generated using UniFFI.
///
/// ## Features
///
/// - **Encryption**: Symmetric and asymmetric encryption with optional AAD
/// - **Password Hashing**: Secure password hashing with configurable parameters
/// - **Secret Sharing**: Shamir's secret sharing implementation
/// - **Digital Signatures**: Ed25519 signing and verification
/// - **Key Generation**: Key pair generation for encryption and signing
///
/// ## Usage
///
/// ```dart
/// import 'package:devolutions_crypto/devolutions_crypto.dart';
///
/// // Generate a key pair
/// final keyPair = generateKeypair();
///
/// // Encrypt data
/// final data = utf8.encode('Hello, World!');
/// final key = List<int>.filled(32, 0); // Your encryption key
/// final encrypted = encrypt(data, key);
///
/// // Hash a password
/// final password = utf8.encode('mySecurePassword');
/// final hash = hashPassword(password);
/// ```
///
/// ## Platform Support
///
/// This package requires native libraries to be built for each platform:
/// - Windows (x64)
/// - Linux (x64)
/// - macOS (x64, ARM64)
/// - Android (arm64-v8a, armeabi-v7a, x86, x86_64)
/// - iOS (arm64, simulators)
///
/// See the README for build instructions.
export 'src/generated/devolutions_crypto.dart';
export 'src/loader.dart';
