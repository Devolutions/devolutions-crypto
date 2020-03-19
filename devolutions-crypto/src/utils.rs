//! Module for utils that does not use any of the Devolutions custom data types.

use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

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
