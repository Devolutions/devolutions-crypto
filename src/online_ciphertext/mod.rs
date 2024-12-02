//! Module for symmetric/asymmetric encryption/decryption.
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
//! in the [Key module](#key).
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

mod online_ciphertext_v1;

use super::CiphertextSubtype;
pub use super::OnlineCiphertextVersion;
use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
use super::Result;

use super::key::{PrivateKey, PublicKey};

use online_ciphertext_v1::{OnlineCiphertextV1Engine, OnlineCiphertextV1Asymmetric, OnlineCiphertextV1Symmetric};

use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

/// A versionned online ciphertext. Can be either symmetric or asymmetric.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct OnlineCiphertext {
    pub(crate) header: Header<OnlineCiphertext>,
    payload: OnlineCiphertextPayload,
}

impl HeaderType for OnlineCiphertext {
    type Version = OnlineCiphertextVersion;
    type Subtype = CiphertextSubtype;

    fn data_type() -> DataType {
        DataType::OnlineCiphertext
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum OnlineCiphertextPayload {
    V1Symmetric(OnlineCiphertextV1Symmetric),
    V1Asymmetric(OnlineCiphertextV1Asymmetric),
}
