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
//! let key: Vec<u8> = generate_key(32).expect("generate key shoudln't fail");
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

use online_ciphertext_v1::{OnlineCiphertextV1Decryptor, OnlineCiphertextV1Encryptor};
use online_ciphertext_v1::{
    OnlineCiphertextV1Header, OnlineCiphertextV1HeaderAsymmetric, OnlineCiphertextV1HeaderSymmetric,
};

use paste::paste;

impl OnlineCiphertextHeader {
    pub fn into_decryptor(self, key: &[u8], aad: &[u8]) -> Result<OnlineCiphertextDecryptor> {
        let mut full_aad: Vec<u8> = self.header.borrow().into();
        full_aad.extend_from_slice(aad);

        match self.payload {
            OnlineCiphertextHeaderPayload::V1(header) => match header {
                OnlineCiphertextV1Header::Symmetric(header) => {
                    let cipher = OnlineCiphertextV1Decryptor::new(key, full_aad, header);

                    Ok(OnlineCiphertextDecryptor::V1(cipher))
                }
                _ => Err(Error::InvalidDataType),
            },
        }
    }

    pub fn into_decryptor_asymmetric(
        self,
        key: &PrivateKey,
        aad: &[u8],
    ) -> Result<OnlineCiphertextDecryptor> {
        let mut full_aad: Vec<u8> = self.header.borrow().into();
        full_aad.extend_from_slice(aad);

        match self.payload {
            OnlineCiphertextHeaderPayload::V1(header) => match header {
                OnlineCiphertextV1Header::Asymmetric(header) => {
                    let cipher = OnlineCiphertextV1Decryptor::new_asymmetric(key, full_aad, header);

                    Ok(OnlineCiphertextDecryptor::V1(cipher))
                }
                _ => Err(Error::InvalidDataType),
            },
        }
    }

    pub fn get_serialized_size(&self) -> usize {
        self.payload.get_serialized_size() + 8
    }

    pub fn get_chunk_size(&self) -> u32 {
        self.payload.get_chunk_size()
    }
}

impl OnlineCiphertextEncryptor {
    pub fn new(
        key: &[u8],
        aad: &[u8],
        chunk_size: u32,
        version: OnlineCiphertextVersion,
    ) -> Result<OnlineCiphertextEncryptor> {
        let header = Header::<OnlineCiphertextHeader> {
            data_subtype: CiphertextSubtype::Symmetric,
            ..Default::default()
        };

        let mut full_aad: Vec<u8> = header.borrow().into();
        full_aad.extend_from_slice(aad);

        match version {
            OnlineCiphertextVersion::V1 | OnlineCiphertextVersion::Latest => {
                let cipher = OnlineCiphertextV1Encryptor::new(key, full_aad, chunk_size)?;

                Ok(OnlineCiphertextEncryptor::V1(cipher))
            }
        }
    }

    pub fn new_asymmetric(
        public_key: &PublicKey,
        aad: &[u8],
        chunk_size: u32,
        version: OnlineCiphertextVersion,
    ) -> Result<OnlineCiphertextEncryptor> {
        let header = Header::<OnlineCiphertextHeader> {
            data_subtype: CiphertextSubtype::Asymmetric,
            ..Default::default()
        };

        let mut full_aad: Vec<u8> = header.borrow().into();
        full_aad.extend_from_slice(aad);

        match version {
            OnlineCiphertextVersion::V1 | OnlineCiphertextVersion::Latest => {
                let cipher =
                    OnlineCiphertextV1Encryptor::new_asymmetric(public_key, full_aad, chunk_size)?;

                Ok(OnlineCiphertextEncryptor::V1(cipher))
            }
        }
    }
}

macro_rules! online_ciphertext_header_impl {
    ($($version_name:ident),+) => {
        paste! {
            /// A versionned online ciphertext.
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

            #[derive(Clone, Debug)]
            enum OnlineCiphertextHeaderPayload {
                $(
                    $version_name([<OnlineCiphertext $version_name Header>]),
                ),+
            }

            impl OnlineCiphertextHeaderPayload {
                pub fn get_serialized_size(&self) -> usize {
                    match &self {
                        $(
                            Self::$version_name(p) => p.get_serialized_size(),
                        ),+
                    }
                }

                pub fn get_chunk_size(&self) -> u32 {
                    match &self {
                        $(
                            Self::$version_name(p) => p.get_chunk_size(),
                        ),+
                    }
                }
            }

            impl From<&OnlineCiphertextHeader> for Vec<u8> {
                fn from(value: &OnlineCiphertextHeader) -> Self {
                    let mut output: Vec<u8> = value.header.borrow().into();
                    let mut payload: Vec<u8> = match &value.payload {
                        $(
                            OnlineCiphertextHeaderPayload::$version_name(p) => {
                                p.into()
                            },
                        ),+
                    };

                    output.append(&mut payload);
                    output
                }
            }

            impl TryFrom<&[u8]> for OnlineCiphertextHeader {
                type Error = Error;

                fn try_from(value: &[u8]) -> Result<Self> {
                    let header = Header::<OnlineCiphertextHeader>::try_from(&value[..8])?;

                    let version = if header.version == OnlineCiphertextVersion::Latest { OnlineCiphertextVersion::V1 } else { header.version };
                    match version {
                        $(
                            OnlineCiphertextVersion::$version_name => {
                                match header.data_subtype {
                                    CiphertextSubtype::Symmetric => {
                                        Ok(Self {
                                            header,
                                            payload:
                                                OnlineCiphertextHeaderPayload::$version_name
                                                    ([<OnlineCiphertext $version_name Header>]::Symmetric
                                                        ([<OnlineCiphertext $version_name HeaderSymmetric>]::try_from(&value[8..])?))
                                        })
                                    }
                                    CiphertextSubtype::Asymmetric => {
                                        Ok(Self {
                                            header,
                                            payload:
                                                OnlineCiphertextHeaderPayload::$version_name
                                                    ([<OnlineCiphertext $version_name Header>]::Asymmetric
                                                        ([<OnlineCiphertext $version_name HeaderAsymmetric>]::try_from(&value[8..])?))
                                        })
                                    }
                                    CiphertextSubtype::None => Err(Error::UnknownSubtype)
                                }
                            }
                        ),+
                        OnlineCiphertextVersion::Latest => unreachable!("Latest is checked before the match arm")
                    }
                }
            }
        }
    };
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

                pub fn get_tag_size(&self) -> usize {
                    match &self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.get_tag_size()
                        }
                    ),+
                    }
                }

                pub fn get_header(&self) -> OnlineCiphertextHeader {
                    match self {
                    $(
                        Self::$version_name(encryptor) => {
                            let data_subtype = encryptor.get_header().get_subtype();
                            OnlineCiphertextHeader {
                                header: Header::<OnlineCiphertextHeader> {
                                    data_subtype,
                                    ..Default::default()
                                },
                                payload: OnlineCiphertextHeaderPayload::$version_name(encryptor.get_header().clone()),
                            }
                        }
                    ),+
                    }
                }

                pub fn [<$func _next_chunk>](
                    &mut self,
                    data: &[u8],
                    aad: &[u8],
                ) -> Result<Vec<u8>> {
                    match self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.[<$func _next_chunk>](data, aad)
                        }
                    ),+
                    }
                }

                pub fn [<$func _next_chunk_in_place>](
                    &mut self,
                    data: &mut Vec<u8>,
                    aad: &[u8],
                ) -> Result<()> {
                    match self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.[<$func _next_chunk_in_place>](data, aad)
                        }
                    ),+
                    }
                }

                pub fn [<$func _last_chunk>](
                    self,
                    data: &[u8],
                    aad: &[u8],
                ) -> Result<Vec<u8>> {
                    match self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.[<$func _last_chunk>](data, aad)
                        }
                    ),+
                    }
                }

                pub fn [<$func _last_chunk_in_place>](
                    self,
                    data: &mut Vec<u8>,
                    aad: &[u8],
                ) -> Result<()> {
                    match self {
                    $(
                        [<OnlineCiphertext $name>]::$version_name(cipher) => {
                            cipher.[<$func _last_chunk_in_place>](data, aad)
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

online_ciphertext_header_impl!(V1);
