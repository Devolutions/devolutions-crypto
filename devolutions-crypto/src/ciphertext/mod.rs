mod ciphertext_v1;
mod ciphertext_v2;

use super::CiphertextSubtype;
pub use super::CiphertextVersion;
use super::DataType;
use super::Error;
use super::Header;
use super::Result;

use super::key::{PrivateKey, PublicKey};

use ciphertext_v1::CiphertextV1;
use ciphertext_v2::{CiphertextV2Asymmetric, CiphertextV2Symmetric};

use std::convert::TryFrom;

#[derive(Clone)]
pub struct Ciphertext {
    pub(crate) header: Header<CiphertextSubtype, CiphertextVersion>,
    payload: CiphertextPayload,
}

#[derive(Clone)]
enum CiphertextPayload {
    V1(CiphertextV1),
    V2Symmetric(CiphertextV2Symmetric),
    V2Asymmetric(CiphertextV2Asymmetric),
}

/// Creates an encrypted data blob from cleartext data and a key.
/// # Arguments
///  * `data` - Data to encrypt.
///  * `key` - Key to use. Can be of arbitrary size.
///  * `version` - Version of the library to encrypt with. Use 0 for default.
/// # Returns
/// Returns a `DcDataBlob` containing the encrypted data.
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

    header.data_type = DataType::Ciphertext;
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

/// Creates an encrypted data blob from cleartext data and a public key.
/// You will need the corresponding private key to decrypt it.
/// # Arguments
///  * `data` - Data to encrypt.
///  * `public_key` - The public key to use. Use either `generate_keypair` or `derive_keypair` for this.
///  * `version` - Version of the library to encrypt with. Use 0 for default.
/// # Returns
/// Returns a `DcDataBlob` containing the encrypted data.
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

    header.data_type = DataType::Ciphertext;
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
    ///  * `key` - Key to use. Can be of arbitrary size.
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

    /// Decrypt the data blob using a private key.
    /// # Arguments
    ///  * `private_key` - Key to use. Must be the one in the same keypair as the public key used for encryption.
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

        if header.data_type != DataType::Ciphertext {
            return Err(Error::InvalidDataType);
        }

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
