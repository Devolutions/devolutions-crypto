// These tests target X25519 (Key V1, Ciphertext V2), which cannot be produced with the `fips` feature
#![cfg(not(feature = "fips"))]

use devolutions_crypto::Error;
use devolutions_crypto::ciphertext::{Ciphertext, CiphertextVersion, encrypt_asymmetric};
use devolutions_crypto::key::{KeyVersion, PublicKey, generate_keypair, mix_key_exchange};
use devolutions_crypto::online_ciphertext::{
    OnlineCiphertextEncryptor, OnlineCiphertextHeader, OnlineCiphertextVersion,
};

use std::convert::TryFrom;

// Curve25519 points of small order, including non-canonical encodings
const LOW_ORDER_POINTS: [[u8; 32]; 7] = [
    hex("0000000000000000000000000000000000000000000000000000000000000000"),
    hex("0100000000000000000000000000000000000000000000000000000000000000"),
    hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
];

const fn hex(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex"),
        }
    }

    let s = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(s[i * 2]) << 4) | nibble(s[i * 2 + 1]);
        i += 1;
    }
    out
}

fn with_last_32(bytes: &[u8], point: &[u8; 32]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let offset = bytes.len() - 32;
    bytes[offset..].copy_from_slice(point);
    bytes
}

fn low_order_public_key(point: &[u8; 32]) -> PublicKey {
    let template: Vec<u8> = generate_keypair(KeyVersion::Latest).public_key.into();
    PublicKey::try_from(with_last_32(&template, point).as_slice()).unwrap()
}

#[test]
fn mix_key_exchange_rejects_low_order_points() {
    let keypair = generate_keypair(KeyVersion::Latest);

    for point in &LOW_ORDER_POINTS {
        let public_key = low_order_public_key(point);
        let result = mix_key_exchange(&keypair.private_key, &public_key);
        assert!(matches!(result, Err(Error::InvalidData)));
    }
}

#[test]
fn encrypt_asymmetric_rejects_low_order_points() {
    for point in &LOW_ORDER_POINTS {
        let public_key = low_order_public_key(point);
        let result = encrypt_asymmetric(b"data", &public_key, CiphertextVersion::Latest);
        assert!(matches!(result, Err(Error::InvalidData)));
    }
}

#[test]
fn decrypt_asymmetric_rejects_low_order_points() {
    let keypair = generate_keypair(KeyVersion::Latest);
    let ciphertext: Vec<u8> =
        encrypt_asymmetric(b"data", &keypair.public_key, CiphertextVersion::Latest)
            .unwrap()
            .into();

    for point in &LOW_ORDER_POINTS {
        // The ephemeral public key follows the 8-byte header
        let mut forged = ciphertext.clone();
        forged[8..40].copy_from_slice(point);

        let forged = Ciphertext::try_from(forged.as_slice()).unwrap();
        let result = forged.decrypt_asymmetric(&keypair.private_key);
        assert!(matches!(result, Err(Error::InvalidData)));
    }
}

#[test]
fn online_ciphertext_rejects_low_order_points() {
    let keypair = generate_keypair(KeyVersion::Latest);
    let encryptor = OnlineCiphertextEncryptor::new_asymmetric(
        &keypair.public_key,
        b"",
        16,
        OnlineCiphertextVersion::Latest,
    )
    .unwrap();
    let header: Vec<u8> = (&encryptor.get_header()).into();

    for point in &LOW_ORDER_POINTS {
        let public_key = low_order_public_key(point);
        let result = OnlineCiphertextEncryptor::new_asymmetric(
            &public_key,
            b"",
            16,
            OnlineCiphertextVersion::Latest,
        );
        assert!(matches!(result, Err(Error::InvalidData)));

        // The ephemeral public key is the last field of the header
        let forged =
            OnlineCiphertextHeader::try_from(with_last_32(&header, point).as_slice()).unwrap();
        let result = forged.into_decryptor_asymmetric(&keypair.private_key, b"");
        assert!(matches!(result, Err(Error::InvalidData)));
    }
}
