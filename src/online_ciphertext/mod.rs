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

use std::borrow::Borrow;

use super::CiphertextSubtype;
use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
pub use super::OnlineCiphertextVersion;
use super::Result;

use super::key::{PrivateKey, PublicKey};

use online_ciphertext_v1::{
    OnlineCiphertextV1Decryptor, OnlineCiphertextV1Encryptor, OnlineCiphertextV1HeaderAsymmetric,
    OnlineCiphertextV1HeaderSymmetric,
};

use paste::paste;

/// A versionned online ciphertext. Can be either symmetric or asymmetric.
#[derive(Clone, Debug)]
pub struct OnlineCiphertextHeader {
    pub(crate) header: Header<OnlineCiphertextHeader>,
    payload: OnlineCiphertextHeaderPayload,
}

impl HeaderType for OnlineCiphertextHeader {
    type Version = OnlineCiphertextVersion;
    type Subtype = CiphertextSubtype;

    fn data_type() -> DataType {
        DataType::OnlineCiphertext
    }
}

pub fn new_encryptor(
    key: &[u8],
    aad: &[u8],
    chunk_size: u32,
    version: OnlineCiphertextVersion,
) -> (OnlineCiphertextEncryptor, OnlineCiphertextHeader) {
    let mut header = Header {
        data_subtype: CiphertextSubtype::Symmetric,
        ..Default::default()
    };

    let mut full_aad: Vec<u8> = header.borrow().into();
    full_aad.extend_from_slice(aad);

    match version {
        OnlineCiphertextVersion::V1 | OnlineCiphertextVersion::Latest => {
            header.version = OnlineCiphertextVersion::V1;

            let (cipher, inner_header) =
                OnlineCiphertextV1Encryptor::new(key, full_aad, chunk_size);

            (
                OnlineCiphertextEncryptor::V1(cipher),
                OnlineCiphertextHeader {
                    header,
                    payload: OnlineCiphertextHeaderPayload::V1Symmetric(inner_header),
                },
            )
        }
    }
}

pub fn new_encryptor_asymmetric(
    public_key: &PublicKey,
    aad: &[u8],
    chunk_size: u32,
    version: OnlineCiphertextVersion,
) -> (OnlineCiphertextEncryptor, OnlineCiphertextHeader) {
    let mut header = Header {
        data_subtype: CiphertextSubtype::Asymmetric,
        ..Default::default()
    };

    let mut full_aad: Vec<u8> = header.borrow().into();
    full_aad.extend_from_slice(aad);

    match version {
        OnlineCiphertextVersion::V1 | OnlineCiphertextVersion::Latest => {
            header.version = OnlineCiphertextVersion::V1;

            let (cipher, inner_header) =
                OnlineCiphertextV1Encryptor::new_asymmetric(public_key, full_aad, chunk_size);

            (
                OnlineCiphertextEncryptor::V1(cipher),
                OnlineCiphertextHeader {
                    header,
                    payload: OnlineCiphertextHeaderPayload::V1Asymmetric(inner_header),
                },
            )
        }
    }
}

impl OnlineCiphertextHeader {
    pub fn get_decryptor(&self, key: &[u8], aad: &[u8]) -> Result<OnlineCiphertextDecryptor> {
        let mut full_aad: Vec<u8> = self.header.borrow().into();
        full_aad.extend_from_slice(aad);

        match &self.payload {
            OnlineCiphertextHeaderPayload::V1Symmetric(header) => {
                let cipher = OnlineCiphertextV1Decryptor::new(key, full_aad, &header);

                Ok(OnlineCiphertextDecryptor::V1(cipher))
            }
            OnlineCiphertextHeaderPayload::V1Asymmetric(_) => Err(Error::InvalidDataType),
        }
    }

    pub fn get_decryptor_asymmetric(
        &self,
        private_key: &PrivateKey,
        aad: &[u8],
    ) -> Result<OnlineCiphertextDecryptor> {
        let mut full_aad: Vec<u8> = self.header.borrow().into();
        full_aad.extend_from_slice(aad);

        match &self.payload {
            OnlineCiphertextHeaderPayload::V1Symmetric(_) => Err(Error::InvalidDataType),
            OnlineCiphertextHeaderPayload::V1Asymmetric(header) => {
                let cipher =
                    OnlineCiphertextV1Decryptor::new_asymmetric(private_key, full_aad, &header);

                Ok(OnlineCiphertextDecryptor::V1(cipher))
            }
        }
    }
}

macro_rules! online_ciphertext_impl {
    ($name:ident, $func:ident, $($version_name:ident),+) => {
        paste! {
            pub enum [<OnlineCiphertext $name>] {
            $(
                $version_name([<OnlineCiphertext $version_name $name>]),
            ),+
            }

            impl [<OnlineCiphertext $name>] {
                pub fn get_chunk_size(&self) -> u32 {
                    match &self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.get_chunk_size()
                        }
                    ),+
                    }
                }

                pub fn [<$func _chunk>](
                    &mut self,
                    data: &[u8],
                    aad: &[u8],
                ) -> Result<Vec<u8>> {
                    match self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.[<$func _chunk>](data, aad)
                        }
                    ),+
                    }
                }

                pub fn [<$func _chunk_in_place>](
                    &mut self,
                    data: &mut Vec<u8>,
                    aad: &[u8],
                ) -> Result<()> {
                    match self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.[<$func _chunk_in_place>](data, aad)
                        }
                    ),+
                    }
                }

                pub fn [<$func _last>](
                    self,
                    data: &[u8],
                    aad: &[u8],
                ) -> Result<Vec<u8>> {
                    match self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.[<$func _last>](data, aad)
                        }
                    ),+
                    }
                }

                pub fn [<$func _last_in_place>](
                    self,
                    data: &mut Vec<u8>,
                    aad: &[u8],
                ) -> Result<()> {
                    match self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.[<$func _last_in_place>](data, aad)
                        }
                    ),+
                    }
                }
            }
        }
    };
}

online_ciphertext_impl!(Encryptor, encrypt, V1);
online_ciphertext_impl!(Decryptor, decrypt, V1);

#[derive(Clone, Debug)]
enum OnlineCiphertextHeaderPayload {
    V1Symmetric(OnlineCiphertextV1HeaderSymmetric),
    V1Asymmetric(OnlineCiphertextV1HeaderAsymmetric),
}
