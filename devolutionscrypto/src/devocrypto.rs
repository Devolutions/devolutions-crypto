use std::convert::TryFrom as _;

use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use rand::{rngs::OsRng, RngCore};

use hmac::Hmac;
use sha2::Sha256;

use pbkdf2::pbkdf2;

use byteorder::{LittleEndian, ReadBytesExt};

use super::dc_data_blob::DcDataBlob;
use super::devocrypto_errors::DevoCryptoError;
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
    let (public, private) = DcDataBlob::generate_key_exchange()?;
    Ok((public.into(), private.into()))
}

pub fn mix_key_exchange(public: &[u8], private: &[u8]) -> Result<Vec<u8>> {
    let signature_pub = &public[0..8];
    let signature_priv = &private[0..8];

    if signature_pub != [0xD, 0xC, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00]
        || signature_priv != [0x0D, 0x0C, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00]
    {
        return Err(DevoCryptoError::InvalidSignature);
    }

    let mut public_sized = [0u8; 32];
    let mut private_sized = [0u8; 32];

    public_sized.copy_from_slice(&public[8..40]);
    private_sized.copy_from_slice(&private[8..40]);

    let shared = x25519(private_sized, public_sized);
    Ok(shared.to_vec())
}

pub fn generate_key(length: usize) -> Result<Vec<u8>> {
    let mut rng = OsRng::new()?;
    let mut key = vec![0u8; length];
    rng.fill_bytes(&mut key);
    Ok(key)
}

pub fn derive_key(key: &[u8], salt: &[u8], niterations: usize, size: usize) -> Vec<u8> {
    let mut new_key = vec![0u8; size];
    pbkdf2::<Hmac<Sha256>>(&key, &salt, niterations, &mut new_key);
    new_key
}

#[test]
fn crypto_test() {
    let key = "012345678".as_bytes();
    let data = "Hello worldasass!!".as_bytes();

    let encrypted = encrypt(data, key).expect("Cannot encrypt");
    let decrypted = decrypt(&encrypted, key).expect("Cannot decrypt");

    println!("{:?}", data);
    println!("{:?}", decrypted);
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
    let (bob_pub, bob_priv) = generate_key_exchange().unwrap();
    let (alice_pub, alice_priv) = generate_key_exchange().unwrap();

    let bob_shared = mix_key_exchange(&alice_pub, &bob_priv).unwrap();
    let alice_shared = mix_key_exchange(&bob_pub, &alice_priv).unwrap();

    assert_eq!(bob_shared, alice_shared);
}
