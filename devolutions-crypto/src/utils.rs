//! Module for utils that does not use any of the Devolutions custom data types.

use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

use super::DataType;
use super::Header;

/// Returns a random key of the specified length. Can also be used
///  whenever you need a random byte array, like for a salt.
/// # Arguments
///  * `length` - Length of the desired key.
/// # Example
/// ```
/// use devolutions_crypto::utils::generate_key;
///
/// let key = generate_key(32);
/// assert_eq!(32, key.len());
/// ```
pub fn generate_key(length: usize) -> Vec<u8> {
    let mut key = vec![0u8; length];
    OsRng.fill_bytes(&mut key);
    key
}

/// Derives a password or key into a new one.
/// # Arguments
///  * `key` - The key or password to derive.
///  * `salt` - The cryptographic salt to be used to add randomness. Can be empty. Recommended size is 16 bytes.
///  * `iterations` - The number of time the key will be derived. A higher number is slower but harder to brute-force.
///                   10 000 iterations are recommended for a password.
///  * `length` - Length of the desired key.
/// # Example
/// ```
/// use devolutions_crypto::utils::{derive_key, generate_key};
/// let key = b"this is a secret password";
/// let salt = generate_key(16);
/// let iterations = 10000;
/// let length = 32;
///
/// let new_key = derive_key(key, &salt, iterations, length);
///
/// assert_eq!(32, new_key.len());
/// ```
pub fn derive_key(key: &[u8], salt: &[u8], iterations: usize, length: usize) -> Vec<u8> {
    let mut new_key = vec![0u8; length];
    pbkdf2::<Hmac<Sha256>>(&key, &salt, iterations, &mut new_key);
    new_key
}

/// Only validate the header to make sure it is valid. Used to quickly determine if the data comes from the library.
/// # Arguments
///  * `data` - The data to verify.
///  * `data_type` - The type of the data.
/// # Returns
/// `true` if the header is valid, `false` if it is not.
/// # Example
/// use devolutions_crypto::DataType;
/// use devolutions_crypto::ciphertext::{encrypt, CiphertextVersion};
/// use devolutions_crypto::utils::{generate_key, validate_signature};
///
/// let key = generate_key(32);
/// let ciphertext: Vec<u8> = encrypt(b"test", &key, CiphertextVersion::Latest).unwrap().into();
///
/// assert!(validate_signature(&ciphertext, DataType::Ciphertext);
/// assert!(!validate_signature(&ciphertext, DataType::PasswordHash);
/// assert!(!validate_signature(&key, DataType::Ciphertext);
pub fn validate_signature(data: &[u8], data_type: DataType) -> bool {
    use super::ciphertext::Ciphertext;
    use super::key::{PrivateKey, PublicKey};
    use super::password_hash::PasswordHash;
    use super::secret_sharing::Share;
    use std::convert::TryFrom;

    if data.len() < Header::len() {
        return false;
    }

    match data_type {
        DataType::None => false,
        DataType::Ciphertext => Header::<Ciphertext>::try_from(&data[0..Header::len()]).is_ok(),
        DataType::PasswordHash => Header::<PasswordHash>::try_from(&data[0..Header::len()]).is_ok(),
        DataType::Key => {
            Header::<PrivateKey>::try_from(&data[0..Header::len()]).is_ok()
                || Header::<PublicKey>::try_from(&data[0..Header::len()]).is_ok()
        }
        DataType::Share => Header::<Share>::try_from(&data[0..Header::len()]).is_ok(),
    }
}

#[test]
fn test_generate_key() {
    let size = 32;
    let key = generate_key(size);

    assert_eq!(size, key.len());
    assert_ne!(vec![0u8; size], key);
}

#[test]
fn test_derive_key() {
    let salt = b"salt";
    let key = b"key";
    let iterations = 100;
    let size = 32;

    let derived = derive_key(key, salt, iterations, size);

    assert_eq!(size, derived.len());
    assert_ne!(vec![0u8; size], derived);
}

#[test]
fn test_validate_signature() {
    use base64::decode;

    let valid_ciphertext = decode("DQwCAAAAAQA=").unwrap();
    let valid_password_hash = decode("DQwDAAAAAQA=").unwrap();
    let valid_share = decode("DQwEAAAAAQA=").unwrap();
    let valid_private_key = decode("DQwBAAEAAQA=").unwrap();
    let valid_public_key = decode("DQwBAAEAAQA=").unwrap();

    assert!(validate_signature(&valid_ciphertext, DataType::Ciphertext));
    assert!(validate_signature(
        &valid_password_hash,
        DataType::PasswordHash
    ));
    assert!(validate_signature(&valid_share, DataType::Share));
    assert!(validate_signature(&valid_private_key, DataType::Key));
    assert!(validate_signature(&valid_public_key, DataType::Key));

    assert!(!validate_signature(
        &valid_ciphertext,
        DataType::PasswordHash
    ));

    let invalid_signature = decode("DAwBAAEAAQA=").unwrap();
    let invalid_type = decode("DQwIAAEAAQA=").unwrap();
    let invalid_subtype = decode("DQwBAAgAAQA=").unwrap();
    let invalid_version = decode("DQwBAAEACAA=").unwrap();

    assert!(!validate_signature(&invalid_signature, DataType::Key));
    assert!(!validate_signature(&invalid_type, DataType::Key));
    assert!(!validate_signature(&invalid_subtype, DataType::Key));
    assert!(!validate_signature(&invalid_version, DataType::Key));

    let not_long_enough = decode("DQwBAAEAAQ==").unwrap();

    assert!(!validate_signature(&not_long_enough, DataType::Key));
}
