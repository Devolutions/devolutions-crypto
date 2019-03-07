//! Cryptographic utils that does not use the Devolutions custom data type

use rand::{rngs::OsRng, RngCore};

use hmac::Hmac;
use sha2::Sha256;

use pbkdf2::pbkdf2;

use super::Result;

/// Returns a random key of the specified length
/// # Arguments
///  * `length` - Length of the key
/// # Example
/// ```
/// use devocrypto::generate_key;
///
/// let key = generate_key(32);
/// assert_eq!(32, key.len());
/// ```
pub fn generate_key(length: usize) -> Result<Vec<u8>> {
    let mut rng = OsRng::new()?;
    let mut key = vec![0u8; length];
    rng.fill_bytes(&mut key);
    Ok(key)
}

/// Derives a key or password into a new one
/// # Arguments
///  * `key` - The key to derive
///  * `salt` - The cryptographic salt to be used to add randomness. Can be empty
///  * `iterations` - The number of time the key will be derived. A higher number is slower but harder to brute-force.
///                   10 000 iterations are recommended for a password
///  * `length` - Length of the desired key
/// # Example
/// ```
/// use devocrypto::derive_key;
/// let key = b"this is a secret password";
/// let salt = b"this is a salt";
/// let iterations = 10000;
/// let length = 32;
///
/// let new_key = derive_key(key, salt, iterations, length);
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
    let key = generate_key(size).unwrap();

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
