//! Cryptographic utils that does not use the Devolutions custom data type.

use super::Result;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use sharks::Sharks;
use zeroize::Zeroize;

use crate::Error;

/// Returns a random key of the specified length.
/// # Arguments
///  * `length` - Length of the key.
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

/// Derives a key or password into a new one.
/// # Arguments
///  * `key` - The key to derive.
///  * `salt` - The cryptographic salt to be used to add randomness. Can be empty.
///  * `iterations` - The number of time the key will be derived. A higher number is slower but harder to brute-force.
///                   10 000 iterations are recommended for a password.
///  * `length` - Length of the desired key.
/// # Example
/// ```
/// use devolutions_crypto::utils::derive_key;
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

pub fn generate_shared_key(n_shares: u8, threshold: u8, length: usize) -> Vec<Vec<u8>> {
    let mut secret = generate_key(length);
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);

    secret.zeroize();

    dealer
        .take(n_shares as usize)
        .map(|s| (&s).into())
        .collect()
}

pub fn join_secret(threshold: u8, shares: &[&[u8]]) -> Result<Vec<u8>> {
    let sharks = Sharks(threshold);

    let shares: Vec<sharks::Share> = shares.iter().map(|s| (*s).into()).collect();
    match sharks.recover(&shares) {
        Ok(x) => Ok(x),
        Err(_) => Err(Error::NotEnoughShares),
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
