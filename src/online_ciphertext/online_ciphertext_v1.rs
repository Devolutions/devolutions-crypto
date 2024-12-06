///! Online Ciphertext V1: STREAM-LE31-XChaCha20Poly1305
use super::{PrivateKey, PublicKey};

use super::Error;
use super::Header;
use super::Result;

use super::OnlineCiphertext;

use std::convert::TryFrom;
use std::ops::Sub;

use aead::generic_array::GenericArray;
use aead::stream::{NewStream, StreamLE31, StreamPrimitive};
use aead::AeadCore;
use chacha20poly1305::aead::{
    stream::{DecryptorLE31, EncryptorLE31},
    Aead, Payload,
};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

use rand::{rngs::OsRng, RngCore};
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

const CONTEXT: &'static str = "devolutions_crypto online_ciphertext_v1";

pub struct OnlineCiphertextV1Encryptor {
    chunk_size: u64,
    cipher: EncryptorLE31<XChaCha20Poly1305>,
}

pub struct OnlineCiphertextV1Decryptor {
    chunk_size: u64,
    cipher: DecryptorLE31<XChaCha20Poly1305>,
}

trait NewOnlineCiphertextV1 {
    type Ciphertext: NewStream<StreamLE31<XChaCha20Poly1305>>;

    fn new(key: &[u8], chunk_size: u64) -> (Self, [u8; 20]) {
        // Generate a new nonce
        let mut nonce = [0u8; 20];
        OsRng.fill_bytes(&mut nonce);

        // Derive the key
        let key = Zeroizing::new(blake3::derive_key(CONTEXT, key));
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());

        // Create the STREAM encryptor
        let cipher = EncryptorLE31::from_aead(cipher, &nonce.into());

        (Self { chunk_size, cipher }, nonce)
    }
}

impl OnlineCiphertextV1Encryptor {
    pub fn new(key: &[u8], chunk_size: u64) -> (Self, [u8; 20]) {
        // Generate a new nonce
        let mut nonce = [0u8; 20];
        OsRng.fill_bytes(&mut nonce);

        // Derive the key
        let key = Zeroizing::new(blake3::derive_key(CONTEXT, key));
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());

        // Create the STREAM encryptor
        let cipher = EncryptorLE31::from_aead(cipher, &nonce.into());

        (Self { chunk_size, cipher }, nonce)
    }

    pub fn encrypt_chunk(
        &mut self,
        data: &[u8],
        header: &Header<OnlineCiphertext>,
    ) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        self.encrypt_in_place(&mut data, header)?;

        Ok(data)
    }

    pub fn encrypt_in_place(
        &mut self,
        data: &mut Vec<u8>,
        header: &Header<OnlineCiphertext>,
    ) -> Result<()> {
        if (data.len() as u64) != self.chunk_size {
            return Err(Error::InvalidChunkLength);
        };

        let header: [u8; 8] = header.into();

        self.cipher.encrypt_next_in_place(&header, data)?;

        Ok(())
    }

    pub fn encrypt_last_chunk(
        self,
        data: &[u8],
        header: &Header<OnlineCiphertext>,
    ) -> Result<Vec<u8>> {
        if (data.len() as u64) >= self.chunk_size {
            return Err(Error::InvalidChunkLength);
        };

        let header: [u8; 8] = header.into();

        let payload = Payload {
            msg: data,
            aad: header.as_slice(),
        };

        Ok(self.cipher.encrypt_last(payload)?)
    }

    pub fn encrypt_last_in_place(
        self,
        data: &mut Vec<u8>,
        header: &Header<OnlineCiphertext>,
    ) -> Result<()> {
        if (data.len() as u64) != self.chunk_size {
            return Err(Error::InvalidChunkLength);
        };

        let header: [u8; 8] = header.into();

        self.cipher.encrypt_last_in_place(&header, data)?;

        Ok(())
    }
}
