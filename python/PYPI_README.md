# devolutions-crypto

[![PyPI version](https://img.shields.io/pypi/v/devolutions-crypto.svg)](https://pypi.org/project/devolutions-crypto/)
[![Python versions](https://img.shields.io/pypi/pyversions/devolutions-crypto.svg)](https://pypi.org/project/devolutions-crypto/)

Cryptographic library used in Devolutions products. It is made to be fast, easy to use and misuse-resistant.

This is the official Python wrapper for the [devolutions-crypto](https://github.com/devolutions/devolutions-crypto) Rust library, providing high-performance cryptographic operations with a simple, Pythonic API.

## Installation

```bash
pip install devolutions-crypto
```

## Features

- **Symmetric Encryption**: Fast AES-256-GCM encryption for shared-key scenarios
- **Asymmetric Encryption**: X25519-based public-key encryption
- **Password Hashing**: Secure password hashing with PBKDF2
- **Digital Signatures**: Ed25519 signatures for data authentication
- **Key Derivation**: PBKDF2 and Argon2 key derivation functions
- **Type Safety**: Full type hints and IDE support via stub files

## Quick Start

```python
import devolutions_crypto
import os

# Generate a random encryption key
key = os.urandom(32)

# Encrypt some data
plaintext = b"Hello, World!"
ciphertext = devolutions_crypto.encrypt(plaintext, key)

# Decrypt it back
decrypted = devolutions_crypto.decrypt(ciphertext, key)
assert decrypted == plaintext
```

## Usage Examples

### Table of Contents

* [Symmetric Encryption](#symmetric-encryption)
* [Asymmetric Encryption](#asymmetric-encryption)
* [Password Hashing](#password-hashing)
* [Digital Signatures](#digital-signatures)
* [Key Derivation](#key-derivation)

### Symmetric Encryption

Use symmetric encryption when both parties share the same secret key.

```python
import devolutions_crypto
import os

# Generate a 32-byte encryption key
key = os.urandom(32)

# Encrypt data
plaintext = b"This is secret data"
ciphertext = devolutions_crypto.encrypt(plaintext, key)

# Decrypt data
decrypted = devolutions_crypto.decrypt(ciphertext, key)
assert decrypted == plaintext
```

#### With Additional Authenticated Data (AAD)

AAD allows you to bind additional context to the ciphertext without encrypting it:

```python
import devolutions_crypto
import os

key = os.urandom(32)
plaintext = b"Secret message"
aad = b"user_id:12345"  # Context data (not encrypted, but authenticated)

# Encrypt with AAD
ciphertext = devolutions_crypto.encrypt(plaintext, key, aad=aad)

# Decrypt with AAD (must match encryption AAD)
decrypted = devolutions_crypto.decrypt(ciphertext, key, aad=aad)
assert decrypted == plaintext

# Decryption fails with wrong or missing AAD
try:
    devolutions_crypto.decrypt(ciphertext, key, aad=b"wrong_context")
except devolutions_crypto.DevolutionsCryptoException:
    print("Authentication failed - AAD mismatch")
```

### Asymmetric Encryption

Use asymmetric encryption when you want to encrypt data for a recipient using their public key.

```python
import devolutions_crypto

# Generate a keypair
keypair = devolutions_crypto.generate_keypair()

# Encrypt data with the public key
plaintext = b"Secret message for Bob"
ciphertext = devolutions_crypto.encrypt_asymmetric(plaintext, keypair.public_key)

# Decrypt with the private key
decrypted = devolutions_crypto.decrypt_asymmetric(ciphertext, keypair.private_key)
assert decrypted == plaintext
```

#### Key Exchange Example

Alice and Bob can establish a shared secret without transmitting it:

```python
import devolutions_crypto

# Alice generates her keypair
alice_keypair = devolutions_crypto.generate_keypair()

# Bob generates his keypair
bob_keypair = devolutions_crypto.generate_keypair()

# They exchange public keys (public keys can be transmitted over insecure channels)

# Alice encrypts a message for Bob using his public key
message = b"Hello Bob!"
ciphertext = devolutions_crypto.encrypt_asymmetric(message, bob_keypair.public_key)

# Bob decrypts the message using his private key
decrypted = devolutions_crypto.decrypt_asymmetric(ciphertext, bob_keypair.private_key)
assert decrypted == message
```

### Password Hashing

Securely hash and verify passwords using PBKDF2:

```python
import devolutions_crypto

# Hash a password (this is slow by design - use high iterations)
password = b"my_secure_password123!"
password_hash = devolutions_crypto.hash_password(
    password,
    iterations=100000,  # Higher is more secure but slower
    version=0
)

# Verify the password
is_valid = devolutions_crypto.verify_password(password, password_hash)
assert is_valid is True

# Wrong password fails verification
is_valid = devolutions_crypto.verify_password(b"wrong_password", password_hash)
assert is_valid is False
```

### Digital Signatures

Sign data to prove authenticity and verify signatures:

#### Generating a Signing Keypair

```python
import devolutions_crypto

# Generate a signing keypair
signing_keypair = devolutions_crypto.generate_signing_keypair()

# Extract the public key
public_key = devolutions_crypto.get_signing_public_key(signing_keypair)
```

#### Signing Data

```python
import devolutions_crypto

# Sign some data
data = b"This is an important message"
signature = devolutions_crypto.sign(data, signing_keypair)
```

#### Verifying Signatures

```python
import devolutions_crypto

# Verify the signature with the public key
is_valid = devolutions_crypto.verify_signature(data, public_key, signature)
assert is_valid is True

# Verification fails for modified data
modified_data = b"This is a tampered message"
is_valid = devolutions_crypto.verify_signature(modified_data, public_key, signature)
assert is_valid is False
```

### Key Derivation

Derive cryptographic keys from passwords or other key material.

#### PBKDF2

```python
import devolutions_crypto
import os

# Derive a key from a password
password = b"user_password"
salt = os.urandom(16)  # Use a unique random salt per user

derived_key = devolutions_crypto.derive_key_pbkdf2(
    password,
    salt=salt,
    iterations=100000,
    length=32
)

# Use the derived key for encryption
plaintext = b"User data"
ciphertext = devolutions_crypto.encrypt(plaintext, derived_key)
```

#### Argon2

```python
import devolutions_crypto

# Derive a key using Argon2 (requires Argon2Parameters)
password = b"user_password"
# parameters should be serialized Argon2Parameters
derived_key = devolutions_crypto.derive_key_argon2(password, parameters)
```

## Supported Python Versions

- Python 3.10+
- Python 3.11
- Python 3.12
- Python 3.13
- Python 3.14

## Supported Platforms

Pre-built wheels are available for:
- **Linux**: x86_64, i686, aarch64
- **macOS**: x86_64 (Intel), aarch64 (Apple Silicon)
- **Windows**: x86, x64, ARM64

## Security Notes

1. **Key Management**: Always use cryptographically secure random number generators (like `os.urandom()`) for key generation
2. **Salt Uniqueness**: Use unique salts for each password/user when deriving keys
3. **Iterations**: Use high iteration counts (100,000+) for password hashing and key derivation
4. **Key Size**: Use 32-byte (256-bit) keys for symmetric encryption
5. **AAD**: Additional Authenticated Data must match exactly between encryption and decryption

## Exception Handling

All functions may raise `DevolutionsCryptoException` on errors:

```python
import devolutions_crypto

try:
    # Invalid key size
    result = devolutions_crypto.encrypt(b"data", b"short_key")
except devolutions_crypto.DevolutionsCryptoException as e:
    print(f"Encryption error: {e}")
```

## Underlying Algorithms

As of the current version:
- **Symmetric encryption**: AES-256-GCM
- **Asymmetric encryption**: X25519 (ECDH) + AES-256-GCM (ECIES)
- **Password hashing**: PBKDF2-HMAC-SHA256
- **Digital signatures**: Ed25519
- **Key derivation**: PBKDF2-HMAC-SHA256, Argon2

## Performance

This library is built on Rust and compiled to native code, providing excellent performance:
- Symmetric encryption/decryption: Millions of operations per second
- Asymmetric operations: Thousands of operations per second
- Password hashing: Intentionally slow (configurable via iterations)

## Contributing

This project is open source. Visit the [GitHub repository](https://github.com/devolutions/devolutions-crypto) to report issues or contribute.

## License

This project is licensed under MIT OR Apache-2.0.
