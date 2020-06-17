//! Module for utils that does not use any of the Devolutions custom data types.

use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

use super::Argon2Parameters;
use super::DataType;
use super::Error;
use super::Header;
use super::Result;

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

/// Derives a password or key into a new one using PBKDF2.
/// # Arguments
///  * `key` - The key or password to derive.
///  * `salt` - The cryptographic salt to be used to add randomness. Can be empty. Recommended size is 16 bytes.
///  * `iterations` - The number of time the key will be derived. A higher number is slower but harder to brute-force.
///                   10 000 iterations are recommended for a password.
///  * `length` - Length of the desired key.
/// # Example
/// ```
/// use devolutions_crypto::utils::{derive_key_pbkdf2, generate_key};
/// let key = b"this is a secret password";
/// let salt = generate_key(16);
/// let iterations = 10000;
/// let length = 32;
///
/// let new_key = derive_key_pbkdf2(key, &salt, iterations, length);
///
/// assert_eq!(32, new_key.len());
/// ```
pub fn derive_key_pbkdf2(key: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
    let mut new_key = vec![0u8; length];
    pbkdf2::<Hmac<Sha256>>(&key, &salt, iterations, &mut new_key);
    new_key
}

/// Derives a password or key into a new one using Argon2.
/// # Arguments
///  * `key` - The key or password to derive.
///  * `parameters` - The `Argon2Parameters` to use.
/// # Example
/// ```
/// use devolutions_crypto::utils::{derive_key_argon2, generate_key};
/// use devolutions_crypto::Argon2Parameters;
/// let key = b"this is a secret password";
/// let parameters = Argon2Parameters::default();
///
/// let new_key = derive_key_argon2(key, &parameters).expect("default parameters should not fail");
///
/// assert_eq!(32, new_key.len());
/// ```
pub fn derive_key_argon2(key: &[u8], parameters: &Argon2Parameters) -> Result<Vec<u8>> {
    parameters.compute(key)
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
/// use devolutions_crypto::utils::{generate_key, validate_header};
///
/// let key = generate_key(32);
/// let ciphertext: Vec<u8> = encrypt(b"test", &key, CiphertextVersion::Latest).unwrap().into();
///
/// assert!(validate_header(&ciphertext, DataType::Ciphertext);
/// assert!(!validate_header(&ciphertext, DataType::PasswordHash);
/// assert!(!validate_header(&key, DataType::Ciphertext);
pub fn validate_header(data: &[u8], data_type: DataType) -> bool {
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

/// Temporarly binded here for a specific use case, don't rely on this.
// Copied and modified from:
// https://github.com/RustCrypto/password-hashing/blob/master/scrypt/src/simple.rs
// Because rand is outdated, I cannot use the crate directly
#[cfg(target_arch = "wasm32")]
pub fn scrypt_simple(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32) -> String {
    use byteorder::{ByteOrder, LittleEndian};

    let params = scrypt::ScryptParams::new(log_n, r, p).expect("params should be valid");

    // 256-bit derived key
    let mut dk = [0u8; 32];

    scrypt::scrypt(password, salt, &params, &mut dk)
        .expect("32 bytes always satisfy output length requirements");

    // usually 128 bytes is enough
    let mut result = String::with_capacity(128);
    result.push_str("$rscrypt$");
    if r < 256 && p < 256 {
        result.push_str("0$");
        let mut tmp = [0u8; 3];
        tmp[0] = log_n;
        tmp[1] = r as u8;
        tmp[2] = p as u8;
        result.push_str(&base64::encode(&tmp));
    } else {
        result.push_str("1$");
        let mut tmp = [0u8; 9];
        tmp[0] = log_n;
        LittleEndian::write_u32(&mut tmp[1..5], r);
        LittleEndian::write_u32(&mut tmp[5..9], p);
        result.push_str(&base64::encode(&tmp));
    }
    result.push('$');
    result.push_str(&base64::encode(&salt));
    result.push('$');
    result.push_str(&base64::encode(&dk));
    result.push('$');

    result
}

pub fn base64_encode(data: &[u8]) -> String {
    base64::encode(data)
}

pub fn base64_encode_url(data: &[u8]) -> String {
    let config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
    base64::encode_config(data, config)
}

pub fn base64_decode(data: &str) -> Result<Vec<u8>> {
    match base64::decode(data) {
        Ok(d) => Ok(d),
        _ => Err(Error::InvalidData),
    }
}

pub fn base64_decode_url(data: &str) -> Result<Vec<u8>> {
    let config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
    match base64::decode_config(data, config) {
        Ok(d) => Ok(d),
        _ => Err(Error::InvalidData),
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
fn test_derive_key_pbkdf2() {
    let salt = b"salt";
    let key = b"key";
    let iterations = 100;
    let size = 32;

    let derived = derive_key_pbkdf2(key, salt, iterations, size);

    assert_eq!(size, derived.len());
    assert_ne!(vec![0u8; size], derived);
}

#[test]
fn test_validate_header() {
    use base64::decode;

    let valid_ciphertext = decode("DQwCAAAAAQA=").unwrap();
    let valid_password_hash = decode("DQwDAAAAAQA=").unwrap();
    let valid_share = decode("DQwEAAAAAQA=").unwrap();
    let valid_private_key = decode("DQwBAAEAAQA=").unwrap();
    let valid_public_key = decode("DQwBAAEAAQA=").unwrap();

    assert!(validate_header(&valid_ciphertext, DataType::Ciphertext));
    assert!(validate_header(
        &valid_password_hash,
        DataType::PasswordHash
    ));
    assert!(validate_header(&valid_share, DataType::Share));
    assert!(validate_header(&valid_private_key, DataType::Key));
    assert!(validate_header(&valid_public_key, DataType::Key));

    assert!(!validate_header(&valid_ciphertext, DataType::PasswordHash));

    let invalid_signature = decode("DAwBAAEAAQA=").unwrap();
    let invalid_type = decode("DQwIAAEAAQA=").unwrap();
    let invalid_subtype = decode("DQwBAAgAAQA=").unwrap();
    let invalid_version = decode("DQwBAAEACAA=").unwrap();

    assert!(!validate_header(&invalid_signature, DataType::Key));
    assert!(!validate_header(&invalid_type, DataType::Key));
    assert!(!validate_header(&invalid_subtype, DataType::Key));
    assert!(!validate_header(&invalid_version, DataType::Key));

    let not_long_enough = decode("DQwBAAEAAQ==").unwrap();

    assert!(!validate_header(&not_long_enough, DataType::Key));
}
