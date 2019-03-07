use rand::{rngs::OsRng, RngCore};

use hmac::Hmac;
use sha2::Sha256;

use pbkdf2::pbkdf2;

use super::Result;

pub fn generate_key(length: usize) -> Result<Vec<u8>> {
    let mut rng = OsRng::new()?;
    let mut key = vec![0u8; length];
    rng.fill_bytes(&mut key);
    Ok(key)
}

pub fn derive_key(key: &[u8], salt: &[u8], iterations: usize, size: usize) -> Vec<u8> {
    let mut new_key = vec![0u8; size];
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
