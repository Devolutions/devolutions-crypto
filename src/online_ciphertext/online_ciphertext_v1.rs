///! Online Ciphertext V1: STREAM-LE31-XChaCha20Poly1305
use super::{PrivateKey, PublicKey};

use super::Error;
use super::Result;

use std::borrow::Borrow;

use chacha20poly1305::aead::{
    stream::{DecryptorLE31, EncryptorLE31},
    Payload,
};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

use rand::{rngs::OsRng, RngCore};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use paste::paste;

const CONTEXT: &'static str = "devolutions_crypto online_ciphertext_v1";

#[derive(Clone, Debug)]
pub struct OnlineCiphertextV1HeaderSymmetric {
    chunk_size: u32,
    nonce: [u8; 20],
}

#[derive(Clone, Debug)]
pub struct OnlineCiphertextV1HeaderAsymmetric {
    chunk_size: u32,
    nonce: [u8; 20],
    public_key: x25519_dalek::PublicKey,
}

impl From<&OnlineCiphertextV1HeaderSymmetric> for Vec<u8> {
    fn from(value: &OnlineCiphertextV1HeaderSymmetric) -> Self {
        let mut buf = value.chunk_size.to_le_bytes().to_vec();
        buf.extend(value.nonce);

        buf
    }
}

impl From<&OnlineCiphertextV1HeaderAsymmetric> for Vec<u8> {
    fn from(value: &OnlineCiphertextV1HeaderAsymmetric) -> Self {
        let mut buf = value.chunk_size.to_le_bytes().to_vec();
        buf.extend(value.nonce);
        buf.extend_from_slice(value.public_key.as_bytes());

        buf
    }
}

macro_rules! online_ciphertext_impl {
    ($struct_name:ident, $cipher_name:ident, $func:ident) => {
        pub struct $struct_name {
            chunk_size: u32,
            aad: Vec<u8>,
            cipher: $cipher_name<XChaCha20Poly1305>,
        }

        impl $struct_name {
            pub fn get_chunk_size(&self) -> u32 {
                self.chunk_size
            }

            paste! {
                pub fn [<$func _chunk>](
                    &mut self,
                    data: &[u8],
                    aad: &[u8],
                ) -> Result<Vec<u8>> {
                    if (data.len() as u32) != self.chunk_size {
                        return Err(Error::InvalidChunkLength);
                    };

                    let mut full_aad = self.aad.to_vec();

                    if !aad.is_empty() {
                        full_aad.extend_from_slice(aad);
                    };

                    let payload = Payload {
                        msg: &data,
                        aad: &full_aad,
                    };

                    Ok(self.cipher.[<$func _next>](payload)?)
                }

                pub fn  [<$func _chunk_in_place>](
                    &mut self,
                    data: &mut Vec<u8>,
                    aad: &[u8],
                ) -> Result<()> {
                    if (data.len() as u32) != self.chunk_size {
                        return Err(Error::InvalidChunkLength);
                    };

                    let mut full_aad = self.aad.to_vec();

                    if !aad.is_empty() {
                        full_aad.extend_from_slice(aad);
                    };

                    self.cipher.[<$func _next_in_place>](&full_aad, data)?;

                    Ok(())
                }

                pub fn [<$func _last>](
                    self,
                    data: &[u8],
                    aad: &[u8],
                ) -> Result<Vec<u8>> {
                    if (data.len() as u32) != self.chunk_size {
                        return Err(Error::InvalidChunkLength);
                    };

                    let mut full_aad = self.aad.to_vec();

                    if !aad.is_empty() {
                        full_aad.extend_from_slice(aad);
                    };

                    let payload = Payload {
                        msg: &data,
                        aad: &full_aad,
                    };

                    Ok(self.cipher.[<$func _last>](payload)?)
                }

                pub fn [<$func _last_in_place>](
                    self,
                    data: &mut Vec<u8>,
                    aad: &[u8],
                ) -> Result<()> {
                    if (data.len() as u32) != self.chunk_size {
                        return Err(Error::InvalidChunkLength);
                    };

                    let mut full_aad = self.aad.to_vec();

                    if !aad.is_empty() {
                        full_aad.extend_from_slice(aad);
                    };

                    self.cipher.[<$func _last_in_place>](&full_aad, data)?;

                    Ok(())
                }
            }
        }
    };
}

impl OnlineCiphertextV1Encryptor {
    pub fn new(
        key: &[u8],
        mut aad: Vec<u8>,
        chunk_size: u32,
    ) -> (Self, OnlineCiphertextV1HeaderSymmetric) {
        // Generate a new nonce
        let mut nonce = [0u8; 20];
        OsRng.fill_bytes(&mut nonce);

        // Derive the key
        let key = Zeroizing::new(blake3::derive_key(CONTEXT, key));
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());

        // Create the STREAM encryptor
        let cipher = EncryptorLE31::from_aead(cipher, &nonce.into());

        // Create aad
        let header = OnlineCiphertextV1HeaderSymmetric { chunk_size, nonce };

        let mut header_bytes: Vec<u8> = header.borrow().into();
        aad.append(&mut header_bytes);

        (
            Self {
                chunk_size,
                aad,
                cipher,
            },
            header,
        )
    }

    pub fn new_asymmetric(
        public_key: &PublicKey,
        mut aad: Vec<u8>,
        chunk_size: u32,
    ) -> (Self, OnlineCiphertextV1HeaderAsymmetric) {
        // Perform a ECDH exchange as per ECIES
        let public_key = x25519_dalek::PublicKey::from(public_key);

        let ephemeral_private_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let ephemeral_public_key = x25519_dalek::PublicKey::from(&ephemeral_private_key);

        let key = ephemeral_private_key.diffie_hellman(&public_key);

        // Generate a new nonce
        let mut nonce = [0u8; 20];
        OsRng.fill_bytes(&mut nonce);

        // Derive the key
        let key = Zeroizing::new(blake3::derive_key(CONTEXT, key.as_bytes()));
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());

        // Create the STREAM encryptor
        let cipher = EncryptorLE31::from_aead(cipher, &nonce.into());

        let header = OnlineCiphertextV1HeaderAsymmetric {
            chunk_size,
            nonce,
            public_key: ephemeral_public_key,
        };

        let mut header_bytes: Vec<u8> = header.borrow().into();
        aad.append(&mut header_bytes);

        let encryptor = Self {
            chunk_size,
            cipher,
            aad,
        };

        (encryptor, header)
    }
}

impl OnlineCiphertextV1Decryptor {
    pub fn new(key: &[u8], mut aad: Vec<u8>, header: &OnlineCiphertextV1HeaderSymmetric) -> Self {
        // Derive the key
        let key = Zeroizing::new(blake3::derive_key(CONTEXT, key));
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());

        // Create the STREAM decryptor
        let cipher = DecryptorLE31::from_aead(cipher, &header.nonce.into());

        let mut header_bytes: Vec<u8> = header.borrow().into();
        aad.append(&mut header_bytes);

        Self {
            chunk_size: header.chunk_size,
            aad,
            cipher,
        }
    }

    pub fn new_asymmetric(
        private_key: &PrivateKey,
        mut aad: Vec<u8>,
        header: &OnlineCiphertextV1HeaderAsymmetric,
    ) -> Self {
        // Perform a ECDH exchange as per ECIES
        let private_key = x25519_dalek::StaticSecret::from(private_key);

        let key = private_key.diffie_hellman(&header.public_key);

        // Derive the key
        let key = Zeroizing::new(blake3::derive_key(CONTEXT, key.as_bytes()));
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());

        // Create the STREAM decryptor
        let cipher = DecryptorLE31::from_aead(cipher, &header.nonce.into());

        let mut header_bytes: Vec<u8> = header.borrow().into();
        aad.append(&mut header_bytes);

        Self {
            chunk_size: header.chunk_size,
            aad,
            cipher,
        }
    }
}

online_ciphertext_impl!(OnlineCiphertextV1Encryptor, EncryptorLE31, encrypt);
online_ciphertext_impl!(OnlineCiphertextV1Decryptor, DecryptorLE31, decrypt);
