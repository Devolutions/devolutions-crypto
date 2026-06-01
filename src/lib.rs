//! Cryptographic library used in Devolutions products. It is made to be fast, easy to use and misuse-resistant.
//!
//! # Usage
//! * [Overview](#overview)
//! * [Ciphertext Module](#ciphertext)
//!     * [Symmetric Encryption](#symmetric)
//!     * [Asymmetric Encryption](#asymmetric)
//! * [Key Module](#key)
//!     * [Key Generation](#generation)
//!     * [Key Exchange](#key-exchange)
//! * [Key Derivation](#key-derivation)
//! * [PasswordHash Module](#passwordhash)
//! * [SecretSharing Module](#secretsharing)
//! * [Utils Module](#utils)
//!     * [Key Generation](#key-generation)
//!     * [Key Derivation](#key-derivation-1)
//!
//! ## Overview
//!
//! This library is split into multiple modules, which are explained below. When
//! dealing with "managed" data, that includes an header and versioning, you deal
//! with structures like `Ciphertext`, `SecretKey`, `PublicKey`, etc.  
//!
//! These structures all implement `TryFrom<&[u8]>` and `Into<Vec<u8>>` to serialize and deserialize data.
//!
//!
//! ## Ciphertext
//!
//! This module contains everything related to encryption. You can use it to encrypt and decrypt data using either a shared secret key or a keypair.
//! The encryption will give you a `Ciphertext`, which has a method to decrypt it.
//!
//! ### Symmetric
//! The library provides a `SecretKey` which can be used as a shared secret to encrypt messages.
//!
//! ```rust
//! use std::convert::TryFrom as _;
//! use devolutions_crypto::key::{generate_secret_key, KeyVersion, SecretKey};
//! use devolutions_crypto::ciphertext::{ encrypt_with_secret_key, CiphertextVersion, Ciphertext };
//!
//! let secret_key = generate_secret_key(KeyVersion::Latest);
//! let data = b"somesecretdata";
//! let encrypted_data = encrypt_with_secret_key(data, &secret_key, CiphertextVersion::Latest).expect("encryption shouldn't fail");
//!
//! // The ciphertext can be serialized to be saved somewhere, passed to another language or over the network.
//! let encrypted_data_vec: Vec<u8> = encrypted_data.into();
//!
//! // When you receive the data as a byte array, you can deserialize it into a struct using TryFrom
//! let ciphertext = Ciphertext::try_from(encrypted_data_vec.as_slice()).expect("deserialization shouldn't fail");
//! let decrypted_data = ciphertext.decrypt_with_secret_key(&secret_key).expect("The decryption shouldn't fail");
//! assert_eq!(decrypted_data, data);
//! ```
//!
//! The key can also be passed as raw bytes.
//!
//! ```rust
//! use devolutions_crypto::utils::generate_key;
//! use devolutions_crypto::ciphertext::{encrypt_with_raw_key, CiphertextVersion, Ciphertext};
//!
//! let key: Vec<u8> = generate_key(32).expect("generate key shouldn't fail");
//! let data = b"somesecretdata";
//!
//! let encrypted_data: Ciphertext = encrypt_with_raw_key(data, &key, CiphertextVersion::Latest).expect("encryption shouldn't fail");
//! let decrypted_data = encrypted_data.decrypt(&key).expect("The decryption shouldn't fail");
//! assert_eq!(decrypted_data, data);
//! ```
//!
//! ### Asymmetric
//! Here, you will need a `PublicKey` to encrypt data and the corresponding
//! `PrivateKey` to decrypt it. You can generate them by using `generate_keypair`
//! in the [Key module](#key).
//!
//! ```rust
//! use devolutions_crypto::key::{generate_keypair, KeyVersion, KeyPair};
//! use devolutions_crypto::ciphertext::{ encrypt_asymmetric, CiphertextVersion, Ciphertext };
//!
//! let keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//! let data = b"somesecretdata";
//!
//! let encrypted_data: Ciphertext = encrypt_asymmetric(data, &keypair.public_key, CiphertextVersion::Latest).expect("encryption shouldn't fail");
//! let decrypted_data = encrypted_data.decrypt_asymmetric(&keypair.private_key).expect("The decryption shouldn't fail");
//! assert_eq!(decrypted_data, data);
//! ```
//!
//! ## Key
//!
//! This module provides secret keys and keypairs.
//!
//! ### Generation
//!
//! Use `generate_secret_key` to a generate a random symmetric key and `generate_keypair` to generate a random keypair.
//!
//! Asymmetric keys have two uses. They can be used to [encrypt and decrypt data](##asymmetric) and to perform a [key exchange](#key-exchange).
//!
//! ```rust
//! use devolutions_crypto::key::{generate_keypair, KeyVersion, KeyPair};
//!
//! let keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//! ```
//!
//! ## Key Derivation
//!
//! The Key Derivation module provides a way to derive a `SecretKey` from a password or passphrase. The derive operation
//! returns a `SecretKey`, and a `DerivationParameters` that can be serialized and reused to derive the same key at a
//! later time.
//!
//! Example with `derive_key`:
//! ```rust
//! use devolutions_crypto::key_derivation::{derive_key, DerivationParameters};
//! use devolutions_crypto::KeyDerivationVersion;
//!
//! let password = b"a very strong password";
//! let (secret_key, params) = derive_key(password, KeyDerivationVersion::Latest).expect("derivation should not fail");
//! // Serialize params to re-derive later:
//! let params_bytes: Vec<u8> = params.into();
//! ```
//!
//! Example with Argon2 (recommended):
//! ```rust
//! use devolutions_crypto::key_derivation::Argon2;
//! let password = b"a very strong password";
//! let argon2 = Argon2::new();
//! let (secret_key, params) = argon2.derive(password).expect("derivation should not fail");
//! // Serialize params to re-derive later:
//! let params_bytes: Vec<u8> = params.into();
//! ```
//!
//! Example with PBKDF2:
//! ```rust
//! use devolutions_crypto::key_derivation::Pbkdf2;
//! let password = b"a very strong password";
//! let pbkdf2 = Pbkdf2::new();
//! let (secret_key, params) = pbkdf2.derive(password).expect("derivation should not fail");
//! ```
//!
//! ### Key Exchange
//!
//! The goal of using a key exchange is to get a shared secret key between
//! two parties without making it possible for users listening on the conversation
//! to guess that shared key.
//! 1. Alice and Bob generate a `KeyPair` each.
//! 2. Alice and Bob exchange their `PublicKey`.
//! 3. Alice mixes her `PrivateKey` with Bob's `PublicKey`. This gives her the shared key.
//! 4. Bob mixes his `PrivateKey` with Alice's `PublicKey`. This gives him the shared key.
//! 5. Both Bob and Alice have the same shared key, which they can use for symmetric encryption for further communications.
//!
//! ```rust
//! use devolutions_crypto::key::{generate_keypair, mix_key_exchange, KeyVersion, KeyPair};
//!
//! let bob_keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//! let alice_keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//!
//! let bob_shared = mix_key_exchange(&bob_keypair.private_key, &alice_keypair.public_key).expect("key exchange shouldn't fail");
//!
//! let alice_shared = mix_key_exchange(&alice_keypair.private_key, &bob_keypair.public_key).expect("key exchange shouldn't fail");
//!
//! // They now have a shared secret!
//! assert_eq!(bob_shared, alice_shared);
//! ```
//!
//! ## PasswordHash
//! You can use this module to hash a password and validate it afterward. This is the recommended way to verify a user password on login.
//! ```rust
//! use devolutions_crypto::password_hash::{hash_password, PasswordHashVersion};
//!
//! let password = b"somesuperstrongpa$$w0rd!";
//!
//! let hashed_password = hash_password(password, PasswordHashVersion::Latest).expect("hash password shouldn't fail");
//!
//! assert!(hashed_password.verify_password(b"somesuperstrongpa$$w0rd!"));
//! assert!(!hashed_password.verify_password(b"someweakpa$$w0rd!"));
//! ```
//!
//! ## SecretSharing
//! This module is used to generate a key that is split in multiple `Share`
//! and that requires a specific amount of them to regenerate the key.  
//! You can think of it as a "Break The Glass" scenario. You can
//! generate a key using this, lock your entire data by encrypting it
//! and then you will need, let's say, 3 out of the 5 administrators to decrypt
//! the data. That data could also be an API key or password of a super admin account.
//!
//! ```rust
//! use devolutions_crypto::secret_sharing::{generate_shared_key, join_shares, SecretSharingVersion, Share};
//!
//! // You want a key of 32 bytes, split between 5 people, and I want a
//! // minimum of 3 of these shares to regenerate the key.
//! let shares: Vec<Share> = generate_shared_key(5, 3, 32, SecretSharingVersion::Latest).expect("generation shouldn't fail with the right parameters");
//!
//! assert_eq!(shares.len(), 5);
//! let key = join_shares(&shares[2..5]).expect("joining shouldn't fail with the right shares");
//! ```
//!
//! ## Utils
//!
//! These are a bunch of functions that can
//! be useful when dealing with the library.
//!
//! ### Key Generation
//!
//! This is a method used to generate a random key. In almost all case, the `length` parameter should be 32.
//!
//! ```rust
//! use devolutions_crypto::utils::generate_key;
//!
//! let key = generate_key(32).expect("generate key shouldn't fail");;
//! assert_eq!(32, key.len());
//! ```
//!
//!
//! ### Key Derivation
//!
//! The library exposes raw methods for key derivation with argon2 and PBKDF2. We recommend using the managed [Key Derivation](#key-derivation) module.
//!
//! ```rust
//! use devolutions_crypto::utils::{generate_key, derive_key_pbkdf2};
//! let key = b"this is a secret password";
//! let salt = generate_key(16).expect("generate key shouldn't fail");;
//! let iterations = 600000;
//! let length = 32;
//!
//! let new_key = derive_key_pbkdf2(key, &salt, iterations, length);
//!
//! assert_eq!(32, new_key.len());
//! ```
//!
//!
//! # Underlying algorithms
//! As of the current version:
//!  * Symmetric cryptography uses XChaCha20Poly1305
//!  * Asymmetric cryptography uses Curve25519.
//!  * Asymmetric encryption uses ECIES.
//!  * Key derivation uses Argon2 or PBKDF2
//!  * Key exchange uses x25519, or ECDH over Curve25519
//!  * Password Hashing uses PBKDF2-HMAC-SHA2-256
//!  * Secret Sharing uses Shamir Secret sharing over GF256
#![allow(clippy::field_reassign_with_default)]

mod argon2parameters;
mod enums;
mod error;
mod header;

pub mod ciphertext;
pub mod key;
pub mod key_derivation;
pub mod online_ciphertext;
pub mod password_hash;
pub mod secret_sharing;
pub mod signature;
pub mod signing_key;
pub mod utils;

use enums::{CiphertextSubtype, PasswordHashSubtype, ShareSubtype, SignatureSubtype};
pub use header::{Header, HeaderType};

pub use enums::{
    CiphertextVersion, DataType, KeyDerivationVersion, KeySubtype, KeyVersion,
    OnlineCiphertextVersion, PasswordHashVersion, SecretSharingVersion, SignatureVersion,
    SigningKeyVersion,
};

pub use argon2::Variant as Argon2Variant;
pub use argon2::Version as Argon2Version;
pub use argon2parameters::defaults as argon2parameters_defaults;
pub use argon2parameters::Argon2Parameters;
pub use argon2parameters::Argon2ParametersBuilder;
pub use error::{Error, Result};
pub use key_derivation::{derive_key, Argon2, DerivationParameters, Pbkdf2};

pub const DEFAULT_KEY_SIZE: usize = 32;
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 600000;

#[cfg(feature = "wbindgen")]
pub mod wasm;
