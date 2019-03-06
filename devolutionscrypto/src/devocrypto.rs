use std::convert::TryFrom as _;

use rand::{rngs::OsRng, RngCore};

use hmac::Hmac;
use sha2::Sha256;

use pbkdf2::pbkdf2;

use super::dc_data_blob::DcDataBlob;
use super::Result;

pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let blob = DcDataBlob::encrypt(data, key)?;
    Ok(blob.into())
}

pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let blob = DcDataBlob::try_from(data)?;
    blob.decrypt(key)
}

pub fn hash_password(pass: &[u8], iterations: u32) -> Result<Vec<u8>> {
    let blob = DcDataBlob::hash_password(pass, iterations)?;
    Ok(blob.into())
}

pub fn verify_password(pass: &[u8], data: &[u8]) -> Result<bool> {
    let blob = DcDataBlob::try_from(data)?;
    blob.verify_password(pass)
}

pub fn generate_key_exchange() -> Result<(Vec<u8>, Vec<u8>)> {
    let (private, public) = DcDataBlob::generate_key_exchange()?;
    Ok((private.into(), public.into()))
}

pub fn mix_key_exchange(private: &[u8], public: &[u8]) -> Result<Vec<u8>> {
    let private = DcDataBlob::try_from(private)?;
    let public = DcDataBlob::try_from(public)?;
    private.mix_key_exchange(public)
}

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
fn crypto_test() {
    let key = "012345678".as_bytes();
    let data = "Hello worldasass!!".as_bytes();

    let encrypted = encrypt(data, key).expect("Cannot encrypt");
    let decrypted = decrypt(&encrypted, key).expect("Cannot decrypt");

    assert_eq!(decrypted, data);
}

#[test]
fn password_test() {
    let pass = "averystrongpassword".as_bytes();
    let niterations = 1234u32;

    let hash = hash_password(pass, niterations).unwrap();

    assert!(verify_password(pass, &hash).unwrap());
    assert!(!verify_password("averybadpassword".as_bytes(), &hash).unwrap())
}

#[test]
fn ecdh_test() {
    let (bob_priv, bob_pub) = generate_key_exchange().unwrap();
    let (alice_priv, alice_pub) = generate_key_exchange().unwrap();

    let bob_shared = mix_key_exchange(&bob_priv, &alice_pub).unwrap();
    let alice_shared = mix_key_exchange(&alice_priv, &bob_pub).unwrap();

    assert_eq!(bob_shared, alice_shared);
}
