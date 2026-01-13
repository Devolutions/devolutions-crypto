# Changelog

All notable changes to the Python package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

## [2026.1.13] - 2026-01-13

**Supported Python versions: 3.10 - 3.14**

### Added

- Method documentation and type stubs (`.pyi` file) for better IDE support
- Comprehensive README for PyPI with usage examples
- Support for Python 3.14

### Changed

- Version numbering changed to calendar versioning (CalVer) format

### Removed

- Dropped support for Python 3.9

## [0.9.2] - 2025-01-28

**Supported Python versions: 3.9 - 3.13**

### Added

- Support for Python 3.13

### Fixed

- Fixed a breaking change in the core library introduced in 0.9.0

### Removed

- Dropped support for Python 3.8

## [0.9.1] - 2024-06-21

**Supported Python versions: 3.8 - 3.12**

### Added

- Support for Additional Authenticated Data (AAD) parameter in `encrypt()` and `decrypt()` functions

### Changed

- Updated dependencies including curve25519-dalek security update

### Removed

- Dropped support for Python 3.7

## [0.9.0] - 2023-10-24

**Supported Python versions: 3.7 - 3.11**

### Added

- `hash_password()` function for password hashing
- `verify_password()` function for password verification
- Support for Python 3.10 and 3.11

## [0.8.0] - 2021-11-25

**Supported Python versions: 3.7 - 3.9**

### Added

- Signature generation and verification support using Ed25519
- `sign()` function for generating signatures
- `verify_signature()` function for verifying signatures
- `generate_signing_keypair()` function for generating signing key pairs
- `get_signing_public_key()` function for extracting public keys
- Support for Python 3.9

### Removed

- Dropped support for Python 3.6

## [0.7.0] - 2021-01-11

**Supported Python versions: 3.6 - 3.8**

### Added

- `derive_key_argon2()` function for Argon2-based key derivation

## [0.6.0] - 2020-07-14

**Supported Python versions: 3.6 - 3.8**

### Added

- Initial release of Python bindings for devolutions-crypto
- `encrypt()` and `decrypt()` functions for symmetric encryption
- `encrypt_asymmetric()` and `decrypt_asymmetric()` functions for public key encryption
- `derive_key_pbkdf2()` function for PBKDF2-based key derivation
- `generate_keypair()` function for generating public/private key pairs
