//! [![Build Status](https://dev.azure.com/devolutions-net/Open%20Source/_apis/build/status/devolutions-crypto?branchName=master)](https://dev.azure.com/devolutions-net/Open%20Source/_build/latest?definitionId=170&branchName=master) [![](https://meritbadge.herokuapp.com/devolutions-crypto)](https://crates.io/crates/devolutions-crypto)  
//! Cryptographic library used in Devolutions products. It is made to be fast, easy to use and misuse-resistant.
//!
//! # Usage
//! * [Overview](#overview)
//! * [Ciphertext Module](#ciphertext)
//!     * [Symmetric Encryption](#symmetric)
//!     * [Asymmetric Encryption](#asymmetric)
//! * [Key Module](#key)
//!     * [Key Generation/Derivation](#generationderivation)
//!     * [Key Exchange](#key-exchange)
//! * [PasswordHash Module](#passwordhash)
//! * [SecretSharing Module](#secretsharing)
//! * [Utils Module](#utils)
//!     * [Key Generation](#key-generation)
//!     * [Key Derivation](#key-derivation)
//!
//! ## Overview
//!
//! The library is splitted into multiple modules, which are explained below. When
//! dealing with "managed" data, that includes an header and versionning, you deal
//! with structures like `Ciphertext`, `PublicKey`, etc.  
//!
//! These all implements `TryFrom<&[u8]>` and `Into<Vec<u8>>` which are the implemented way to serialize and deserialize data.
//!
//! ```rust
//! use std::convert::TryFrom as _;
//! use devolutions_crypto::utils::generate_key;
//! use devolutions_crypto::ciphertext::{ encrypt, CiphertextVersion, Ciphertext };
//!
//! let key: Vec<u8> = generate_key(32);
//!
//! let data = b"somesecretdata";
//!
//! let encrypted_data: Ciphertext = encrypt(data, &key, CiphertextVersion::Latest).expect("encryption shouldn't fail");
//!
//! // The ciphertext can be serialized.
//! let encrypted_data_vec: Vec<u8> = encrypted_data.into();
//!
//! // This data can be saved somewhere, passed to another language or over the network
//! // ...
//! // When you receive the data as a byte array, you can deserialize it into a struct using TryFrom
//!
//! let ciphertext = Ciphertext::try_from(encrypted_data_vec.as_slice()).expect("deserialization shouldn't fail");
//!
//! let decrypted_data = ciphertext.decrypt(&key).expect("The decryption shouldn't fail");
//!
//! assert_eq!(decrypted_data, data);
//! ```
//!
//! ## Ciphertext
//!
//! This module contains everything related to encryption. You can use it to encrypt and decrypt data using either a shared key of a keypair.  
//! Either way, the encryption will give you a `Ciphertext`, which has a method to decrypt it.
//!
//! ### Symmetric
//!
//! ```rust
//! use devolutions_crypto::utils::generate_key;
//! use devolutions_crypto::ciphertext::{ encrypt, CiphertextVersion, Ciphertext };
//!
//! let key: Vec<u8> = generate_key(32);
//!
//! let data = b"somesecretdata";
//!
//! let encrypted_data: Ciphertext = encrypt(data, &key, CiphertextVersion::Latest).expect("encryption shouldn't fail");
//!
//! let decrypted_data = encrypted_data.decrypt(&key).expect("The decryption shouldn't fail");
//!
//! assert_eq!(decrypted_data, data);
//! ```
//!
//! ### Asymmetric
//! Here, you will need a `PublicKey` to encrypt data and the corresponding
//! `PrivateKey` to decrypt it. You can generate them by using `generate_keypair`
//! or `derive_keypair` in the [Key module](#key).
//!
//! ```rust
//! use devolutions_crypto::key::{generate_keypair, KeyVersion, KeyPair};
//! use devolutions_crypto::ciphertext::{ encrypt_asymmetric, CiphertextVersion, Ciphertext };
//!
//! let keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//!
//! let data = b"somesecretdata";
//!
//! let encrypted_data: Ciphertext = encrypt_asymmetric(data, &keypair.public_key, CiphertextVersion::Latest).expect("encryption shouldn't fail");
//!
//! let decrypted_data = encrypted_data.decrypt_asymmetric(&keypair.private_key).expect("The decryption shouldn't fail");
//!
//! assert_eq!(decrypted_data, data);
//! ```
//!
//! ## Key
//!
//! For now, this module only deal with keypairs, as the symmetric keys are not wrapped yet.
//!
//! ### Generation/Derivation
//!
//! You have two ways to generate a `KeyPair`: Using `generate_keypair` will generate a random one, using `derive_keypair` will derive one from another password or key along with derivation parameters(including salt). Except in specific circumstances, you should use `generate_keypair`.  
//!
//! Asymmetric keys have two uses. They can be used to [encrypt and decrypt data](##asymmetric) and to perform a [key exchange](#key-exchange).
//!
//! #### `generate_keypair`
//! ```rust
//! use devolutions_crypto::key::{generate_keypair, KeyVersion, KeyPair};
//!
//! let keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//! ```
//!
//! #### `derive_keypair`
//! ```rust
//! use devolutions_crypto::Argon2Parameters;
//! use devolutions_crypto::key::{KeyVersion, KeyPair, derive_keypair};
//!
//! let parameters: Argon2Parameters = Default::default();
//! let keypair: KeyPair = derive_keypair(b"thisisapassword", &parameters, KeyVersion::Latest).expect("derivation should not fail");
//! ```
//!
//! ### Key Exchange
//!
//! The goal of using a key exchange is to get a shared secret key between
//! two parties without making it possible for users listening on the conversation
//! to guess that shared key.
//! 1. Alice and Bob generates a `KeyPair` each.
//! 2. Alice and Bob exchanges their `PublicKey`.
//! 3. Alice mix her `PrivateKey` with Bob's `PublicKey`. This gives her the shared key.
//! 4. Bob mixes his `PrivateKey` with Alice's `PublicKey`. This gives him the shared key.
//! 5. Both Bob and Alice has the same shared key, which they can use for symmetric encryption for further communications.
//!
//! ```rust
//! use devolutions_crypto::key::{generate_keypair, mix_key_exchange, KeyVersion, KeyPair};
//!
//! let bob_keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//! let alice_keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//!
//! let bob_shared = mix_key_exchange(&bob_keypair.private_key, &alice_keypair.public_key).expect("key exchange should not fail");
//!
//! let alice_shared = mix_key_exchange(&alice_keypair.private_key, &bob_keypair.public_key).expect("key exchange should not fail");
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
//! let hashed_password = hash_password(password, 10000, PasswordHashVersion::Latest);
//!
//! assert!(hashed_password.verify_password(b"somesuperstrongpa$$w0rd!"));
//! assert!(!hashed_password.verify_password(b"someweakpa$$w0rd!"));
//! ```
//!
//! ## SecretSharing
//! This module is used to generate a key that is splitted in multiple `Share`
//! and that requires a specific amount of them to regenerate the key.  
//! You can think of it as a "Break The Glass" scenario. You can
//! generate a key using this, lock your entire data by encrypting it
//! and then you will need, let's say, 3 out of the 5 administrators to decrypt
//! the data. That data could also be an API key or password of a super admin account.
//!
//! ```rust
//! use devolutions_crypto::secret_sharing::{generate_shared_key, join_shares, SecretSharingVersion, Share};
//!
//! // You want a key of 32 bytes, splitted between 5 people, and I want a
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
//! let key = generate_key(32);
//! assert_eq!(32, key.len());
//! ```
//!
//! ### Key Derivation
//!
//! This is a method used to generate a key from a password or another key. Useful for password-dependant cryptography. Salt should be a random 16 bytes array if possible and iterations should be 10000 or configurable by the user.
//!
//! ```rust
//! use devolutions_crypto::utils::{generate_key, derive_key_pbkdf2};
//! let key = b"this is a secret password";
//! let salt = generate_key(16);
//! let iterations = 10000;
//! let length = 32;
//!
//! let new_key = derive_key_pbkdf2(key, &salt, iterations, length);
//!
//! assert_eq!(32, new_key.len());
//! ```
//!
//! # Underlying algorithms
//! As of the current version:
//!  * Symmetric cryptography uses XChaCha20Poly1305
//!  * Asymmetric cryptography uses Curve25519.
//!  * Asymmetric encryption uses ECIES.
//!  * Key exchange uses x25519, or ECDH over Curve25519
//!  * Password Hashing uses PBKDF2-HMAC-SHA2-256
//!  * Secret Sharing uses Shamir Secret sharing over GF256

mod argon2parameters;
mod enums;
mod error;
mod header;

pub mod ciphertext;
pub mod key;
pub mod password_hash;
pub mod secret_sharing;
pub mod utils;

use enums::{CiphertextSubtype, KeySubtype, PasswordHashSubtype, ShareSubtype};
pub use header::{Header, HeaderType};

pub use enums::{
    CiphertextVersion, DataType, KeyVersion, PasswordHashVersion, SecretSharingVersion,
};

pub use argon2parameters::Argon2Parameters;
pub use error::Error;

type Result<T> = std::result::Result<T, error::Error>;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod python;
