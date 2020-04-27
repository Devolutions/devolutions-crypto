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

mod ciphertext_v1;
mod ciphertext_v2;

use super::CiphertextSubtype;
pub use super::CiphertextVersion;
use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
use super::Result;

use super::key::{PrivateKey, PublicKey};

use ciphertext_v1::CiphertextV1;
use ciphertext_v2::{CiphertextV2Asymmetric, CiphertextV2Symmetric};

use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

/// A versionned ciphertext. Can be either symmetric or asymmetric.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct Ciphertext {
    pub(crate) header: Header<Ciphertext>,
    payload: CiphertextPayload,
}

impl HeaderType for Ciphertext {
    type Version = CiphertextVersion;
    type Subtype = CiphertextSubtype;

    fn data_type() -> DataType {
        DataType::Ciphertext
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum CiphertextPayload {
    V1(CiphertextV1),
    V2Symmetric(CiphertextV2Symmetric),
    V2Asymmetric(CiphertextV2Asymmetric),
}

/// Returns an `Ciphertext` from cleartext data and a key.
/// # Arguments
///  * `data` - The data to encrypt.
///  * `key` - The key to use. The recommended size is 32 bytes.
///  * `version` - Version of the library to encrypt with. Use `CiphertTextVersion::Latest` if you're not dealing with shared data.
/// # Returns
/// Returns a `Ciphertext` containing the encrypted data.
/// # Example
/// ```rust
/// use devolutions_crypto::ciphertext::{ encrypt, CiphertextVersion };
///
/// let data = b"somesecretdata";
/// let key = b"somesecretkey";
///
/// let encrypted_data = encrypt(data, key, CiphertextVersion::Latest).unwrap();
/// ```
pub fn encrypt(data: &[u8], key: &[u8], version: CiphertextVersion) -> Result<Ciphertext> {
    let mut header = Header::default();

    header.data_subtype = CiphertextSubtype::Symmetric;

    let payload = match version {
        CiphertextVersion::V1 => {
            header.version = CiphertextVersion::V1;
            CiphertextPayload::V1(CiphertextV1::encrypt(data, key, &header)?)
        }
        CiphertextVersion::V2 | CiphertextVersion::Latest => {
            header.version = CiphertextVersion::V2;
            CiphertextPayload::V2Symmetric(CiphertextV2Symmetric::encrypt(data, key, &header)?)
        } //_ => return Err(DevoCryptoError::UnknownVersion),
    };

    Ok(Ciphertext { header, payload })
}

/// Returns an `Ciphertext` from cleartext data and a `PublicKey`.
/// You will need the corresponding `PrivateKey` to decrypt it.
/// # Arguments
///  * `data` - The data to encrypt.
///  * `public_key` - The `PublicKey` to use. Use either `generate_keypair` or `derive_keypair` to generate a keypair.
///  * `version` - Version of the library to encrypt with. Use `CiphertTextVersion::Latest` if you're not dealing with shared data.
/// # Returns
/// Returns a `Ciphertext` containing the encrypted data.
/// # Example
/// ```rust
/// use devolutions_crypto::ciphertext::{ encrypt_asymmetric, CiphertextVersion };
/// use devolutions_crypto::key::{ generate_keypair, KeyVersion };
///
/// let data = b"somesecretdata";
/// let keypair = generate_keypair(KeyVersion::Latest);
///
/// let encrypted_data = encrypt_asymmetric(data, &keypair.public_key, CiphertextVersion::Latest).unwrap();
/// ```
pub fn encrypt_asymmetric(
    data: &[u8],
    public_key: &PublicKey,
    version: CiphertextVersion,
) -> Result<Ciphertext> {
    let mut header = Header::default();

    header.data_subtype = CiphertextSubtype::Asymmetric;

    let payload = match version {
        CiphertextVersion::V2 | CiphertextVersion::Latest => {
            header.version = CiphertextVersion::V2;
            CiphertextPayload::V2Asymmetric(CiphertextV2Asymmetric::encrypt(
                data, public_key, &header,
            )?)
        }
        _ => return Err(Error::UnknownVersion),
    };

    Ok(Ciphertext { header, payload })
}

impl Ciphertext {
    /// Decrypt the data blob using a key.
    /// # Arguments
    ///  * `key` - Key to use. The recommended size is 32 bytes.
    /// # Returns
    /// Returns the decrypted data.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::ciphertext::{ encrypt, CiphertextVersion};
    ///
    /// let data = b"somesecretdata";
    /// let key = b"somesecretkey";
    ///
    /// let encrypted_data = encrypt(data, key, CiphertextVersion::Latest).unwrap();
    /// let decrypted_data = encrypted_data.decrypt(key).unwrap();
    ///
    /// assert_eq!(data.to_vec(), decrypted_data);
    ///```
    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>> {
        match &self.payload {
            CiphertextPayload::V1(x) => x.decrypt(key, &self.header),
            CiphertextPayload::V2Symmetric(x) => x.decrypt(key, &self.header),
            _ => Err(Error::InvalidDataType),
        }
    }

    /// Decrypt the data blob using a `PrivateKey`.
    /// # Arguments
    ///  * `private_key` - Key to use. Must be the one in the same keypair as the `PublicKey` used for encryption.
    /// # Returns
    /// Returns the decrypted data.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::ciphertext::{ encrypt_asymmetric, CiphertextVersion };
    /// use devolutions_crypto::key::{ generate_keypair, KeyVersion };
    ///
    /// let data = b"somesecretdata";
    /// let keypair = generate_keypair(KeyVersion::Latest);
    ///
    /// let encrypted_data = encrypt_asymmetric(data, &keypair.public_key, CiphertextVersion::Latest).unwrap();
    /// let decrypted_data = encrypted_data.decrypt_asymmetric(&keypair.private_key).unwrap();
    ///
    /// assert_eq!(decrypted_data, data);
    ///```
    pub fn decrypt_asymmetric(&self, private_key: &PrivateKey) -> Result<Vec<u8>> {
        match &self.payload {
            CiphertextPayload::V2Asymmetric(x) => x.decrypt(private_key, &self.header),
            CiphertextPayload::V1(_) => Err(Error::UnknownVersion),
            _ => Err(Error::InvalidDataType),
        }
    }
}

impl From<Ciphertext> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: Ciphertext) -> Self {
        let mut header: Self = data.header.into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = Error;

    /// Parses the data. Can return an Error of the data is invalid or unrecognized.
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        };

        let header = Header::try_from(&data[0..Header::len()])?;

        let payload = match header.version {
            CiphertextVersion::V1 => {
                CiphertextPayload::V1(CiphertextV1::try_from(&data[Header::len()..])?)
            }
            CiphertextVersion::V2 => match header.data_subtype {
                CiphertextSubtype::Symmetric | CiphertextSubtype::None => {
                    CiphertextPayload::V2Symmetric(CiphertextV2Symmetric::try_from(
                        &data[Header::len()..],
                    )?)
                }
                CiphertextSubtype::Asymmetric => CiphertextPayload::V2Asymmetric(
                    CiphertextV2Asymmetric::try_from(&data[Header::len()..])?,
                ),
            },
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<CiphertextPayload> for Vec<u8> {
    fn from(data: CiphertextPayload) -> Self {
        match data {
            CiphertextPayload::V1(x) => x.into(),
            CiphertextPayload::V2Symmetric(x) => x.into(),
            CiphertextPayload::V2Asymmetric(x) => x.into(),
        }
    }
}

#[test]
fn encrypt_decrypt_test() {
    let key = "0123456789abcdefghijkl".as_bytes();
    let data = "This is a very complex string of character that we need to encrypt".as_bytes();

    let encrypted = encrypt(data, &key, CiphertextVersion::Latest).unwrap();

    let encrypted: Vec<u8> = encrypted.into();

    let encrypted = Ciphertext::try_from(encrypted.as_slice()).unwrap();
    let decrypted = encrypted.decrypt(key).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn encrypt_decrypt_v1_test() {
    let key = "0123456789abcdefghijkl".as_bytes();
    let data = "This is a very complex string of character that we need to encrypt".as_bytes();

    let encrypted = encrypt(data, &key, CiphertextVersion::V1).unwrap();

    assert_eq!(encrypted.header.version, CiphertextVersion::V1);
    let encrypted: Vec<u8> = encrypted.into();

    let encrypted = Ciphertext::try_from(encrypted.as_slice()).unwrap();
    let decrypted = encrypted.decrypt(key).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn encrypt_decrypt_v2_test() {
    let key = "0123456789abcdefghijkl".as_bytes();
    let data = "This is a very complex string of character that we need to encrypt".as_bytes();

    let encrypted = encrypt(data, &key, CiphertextVersion::V2).unwrap();

    assert_eq!(encrypted.header.version, CiphertextVersion::V2);
    let encrypted: Vec<u8> = encrypted.into();

    let encrypted = Ciphertext::try_from(encrypted.as_slice()).unwrap();
    let decrypted = encrypted.decrypt(key).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn asymmetric_test() {
    use super::key::{derive_keypair, KeyVersion};
    use super::Argon2Parameters;

    let test_plaintext = b"this is a test data";
    let test_password = b"test password";

    let mut params = Argon2Parameters::default();
    params.memory = 32;
    params.iterations = 2;

    let keypair = derive_keypair(test_password, &params, KeyVersion::Latest).unwrap();

    let encrypted_data =
        encrypt_asymmetric(test_plaintext, &keypair.public_key, CiphertextVersion::V2).unwrap();

    let encrypted_data_vec: Vec<u8> = encrypted_data.into();

    assert_ne!(encrypted_data_vec.len(), 0);

    let encrypted_data = Ciphertext::try_from(encrypted_data_vec.as_slice()).unwrap();

    let decrypted_data = encrypted_data
        .decrypt_asymmetric(&keypair.private_key)
        .unwrap();

    assert_eq!(decrypted_data, test_plaintext);
}

#[test]
fn asymmetric_test_v2() {
    use super::key::{derive_keypair, KeyVersion};
    use super::Argon2Parameters;

    let test_plaintext = b"this is a test data";
    let test_password = b"test password";

    let mut params = Argon2Parameters::default();
    params.memory = 32;
    params.iterations = 2;

    let keypair = derive_keypair(test_password, &params, KeyVersion::Latest).unwrap();

    let encrypted_data =
        encrypt_asymmetric(test_plaintext, &keypair.public_key, CiphertextVersion::V2).unwrap();

    assert_eq!(encrypted_data.header.version, CiphertextVersion::V2);
    let encrypted_data_vec: Vec<u8> = encrypted_data.into();

    assert_ne!(encrypted_data_vec.len(), 0);

    let encrypted_data = Ciphertext::try_from(encrypted_data_vec.as_slice()).unwrap();

    let decrypted_data = encrypted_data
        .decrypt_asymmetric(&keypair.private_key)
        .unwrap();

    assert_eq!(decrypted_data, test_plaintext);
}
