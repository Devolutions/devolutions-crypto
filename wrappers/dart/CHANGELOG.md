# Changelog

All notable changes to the Devolutions Crypto Dart bindings will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.3] - 2025-12-23

### Added

- Initial release of Dart bindings for Devolutions Crypto
- Support for symmetric encryption (ChaCha20-Poly1305, AES)
- Support for asymmetric encryption (X25519)
- Password hashing with multiple algorithms (PBKDF2, Argon2)
- Shamir's Secret Sharing implementation
- Ed25519 digital signatures
- Key pair generation for encryption and signing
- Cross-platform support (Windows, Linux, macOS, Android, iOS)
- UniFFI-based bindings using uniffi-dart
- Comprehensive example code
- Basic test suite
- Build automation with Makefile
- Native library loader for automatic platform detection

### Documentation

- Complete README with installation and usage instructions
- API reference in library documentation
- Example programs demonstrating all features
- Build instructions for all supported platforms

### Infrastructure

- Generation script for creating Dart bindings from Rust
- Makefile for building native libraries
- GitIgnore configuration for generated files
- Dart analysis and linting configuration
- pub.dev-ready package structure

## [Unreleased]

### Planned

- Additional encryption algorithms
- More comprehensive test coverage
- Performance benchmarks
- Integration examples with Flutter apps
- Improved error messages and documentation
- CI/CD pipeline for automated testing and building
- Pre-built native libraries for easier installation

---

## Version History

The version numbers follow the main Devolutions Crypto library version (0.9.3).
Future versions will be synchronized with the main library releases.

For changes in the underlying Rust library, see the [main CHANGELOG](../../CHANGELOG.md).
