use std::io::Cursor;

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};

use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use rand::{rngs::OsRng, RngCore};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use pbkdf2::pbkdf2;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use super::devocrypto_errors::DevoCryptoError;
use super::Result;

pub fn split_key(secret: &[u8], encryption_key: &mut [u8], signature_key: &mut [u8]) {
    let salt = b"\x00";
    pbkdf2::<Hmac<Sha256>>(secret, &salt[0..1], 1, encryption_key);

    let salt = b"\x01";
    pbkdf2::<Hmac<Sha256>>(secret, &salt[0..1], 1, signature_key);
}

pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Split keys
    let mut encryption_key = vec![0u8; 32];
    let mut signature_key = vec![0u8; 32];
    split_key(key, &mut encryption_key, &mut signature_key);

    // Generate IV
    let mut rng = OsRng::new()?;
    let mut iv = vec![0u8; 16];
    rng.fill_bytes(&mut iv);

    // Create cipher object
    let cipher = Cbc::<Aes256, Pkcs7>::new_var(&encryption_key, &iv)?;
    let mut result = cipher.encrypt_vec(data);

    // Append data
    let mut final_result = vec![0x0D, 0x0C, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
    final_result.append(&mut iv);
    final_result.append(&mut result);

    // HMAC
    let mut mac = Hmac::<Sha256>::new_varkey(&signature_key)?;
    mac.input(&final_result);

    let mut mac_result = mac.result().code().to_vec();

    final_result.append(&mut mac_result);

    Ok(final_result)
}

pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Split keys
    let mut encryption_key = vec![0u8; 32];
    let mut signature_key = vec![0u8; 32];
    split_key(key, &mut encryption_key, &mut signature_key);

    // Verify signature
    let signature = &data[0..8];

    if signature != [0x0D, 0x0C, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00] {
        return Err(DevoCryptoError::InvalidSignature);
    }

    // Verify HMAC
    let data_mac = &data[data.len() - 32..];

    let mut mac = Hmac::<Sha256>::new_varkey(&signature_key)?;
    mac.input(&data[0..data.len() - 32]);
    mac.verify(&data_mac)?;

    let iv = &data[8..24];
    let data = &data[24..data.len() - 32];

    let cipher = Cbc::<Aes256, Pkcs7>::new_var(&encryption_key, &iv)?;
    let result = cipher.decrypt_vec(data)?;

    Ok(result)
}

pub fn hash_password(pass: &[u8], niterations: u32) -> Result<Vec<u8>> {
    // Generate salt
    let mut rng = OsRng::new()?;
    let mut salt = vec![0u8; 32];
    rng.fill_bytes(&mut salt);

    // Prepare data
    let mut signature = vec![0x0D, 0x0C, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00];
    let mut vec_iterations = Vec::new();
    vec_iterations.write_u32::<LittleEndian>(niterations)?;

    // Generate hash
    let mut res = vec![0u8; 32];
    pbkdf2::<Hmac<Sha256>>(pass, &salt, niterations as usize, &mut res);

    // Put all information together
    let mut final_result = Vec::new();
    final_result.append(&mut signature);
    final_result.append(&mut vec_iterations);
    final_result.append(&mut salt);
    final_result.append(&mut res);

    Ok(final_result)
}

pub fn verify_password(pass: &[u8], hash: &[u8]) -> Result<bool> {
    // Verify signature
    let signature = &hash[0..8];

    if signature != [0x0D, 0x0C, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00] {
        return Err(DevoCryptoError::InvalidSignature);
    }

    // Get metadata
    let mut vec_iterations = Cursor::new(&hash[8..12]);
    let niterations = vec_iterations.read_u32::<LittleEndian>()?;
    let salt = &hash[12..44];

    let mut res = vec![0u8; 32];

    pbkdf2::<Hmac<Sha256>>(pass, salt, niterations as usize, &mut res);

    Ok(res == &hash[44..])
}

pub fn generate_key_exchange() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut signature_pub = vec![0x0D, 0x0C, 0x01, 0x00];
    let mut signature_priv = signature_pub.clone();

    signature_pub.append(&mut vec![0x01, 0x00, 0x01, 0x00]);
    signature_priv.append(&mut vec![0x02, 0x00, 0x01, 0x00]);

    let mut rng = OsRng::new()?;
    let mut private = [0u8; 32];

    rng.fill_bytes(&mut private);

    let mut private_vec = private.to_vec();

    let public = x25519(private, X25519_BASEPOINT_BYTES);

    signature_pub.append(&mut public.to_vec());
    signature_priv.append(&mut private_vec);
    Ok((signature_pub, signature_priv))
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
    let key = "01234567".as_bytes();
    let data = "Hello world!".as_bytes();

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
fn split_key_test() {
    let secret = "averystrongpassword".as_bytes();

    let mut crypto_key = vec![0u8; 32];
    let mut signature_key = vec![0u8; 32];

    split_key(&secret, &mut crypto_key, &mut signature_key);

    assert_eq!(crypto_key.len(), 32);
    assert_eq!(signature_key.len(), 32);
    assert_ne!(crypto_key, signature_key);
}

#[test]
fn ecdh_test() {
    let (bob_pub, bob_priv) = generate_key_exchange().unwrap();
    let (alice_pub, alice_priv) = generate_key_exchange().unwrap();

    let bob_shared = mix_key_exchange(&alice_pub, &bob_priv).unwrap();
    let alice_shared = mix_key_exchange(&bob_pub, &alice_priv).unwrap();

    assert_eq!(bob_shared, alice_shared);
}
