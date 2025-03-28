//! Online Ciphertext V1: STREAM-LE31-XChaCha20Poly1305
use super::{PrivateKey, PublicKey};
use crate::enums::CiphertextSubtype;

use super::Error;
use super::Result;

use std::borrow::Borrow;

use chacha20poly1305::aead::{
    stream::{DecryptorLE31, EncryptorLE31},
    Payload,
};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use rand::TryRngCore;

use paste::paste;

/// Context string for the Blake3 KDF function.
/// This is used to normalize the key length and domain separation
const CONTEXT: &str = "devolutions_crypto online_ciphertext_v1";

#[derive(Clone, Debug)]
pub enum OnlineCiphertextV1Header {
    Symmetric(OnlineCiphertextV1HeaderSymmetric),
    Asymmetric(OnlineCiphertextV1HeaderAsymmetric),
}

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

impl OnlineCiphertextV1Header {
    pub fn get_serialized_size(&self) -> usize {
        match self {
            Self::Symmetric(_) => {
                // chunk_size (u32, so 4 bytes) + 20 bytes nonce
                20 + 4
            }
            Self::Asymmetric(_) => {
                // chunk_size (u32, so 4 bytes) + 20 bytes nonce + 32 bytes public key
                20 + 4 + 32
            }
        }
    }

    pub fn get_chunk_size(&self) -> u32 {
        match self {
            Self::Symmetric(x) => x.chunk_size,
            Self::Asymmetric(x) => x.chunk_size,
        }
    }

    pub fn get_subtype(&self) -> CiphertextSubtype {
        match self {
            Self::Symmetric(_) => CiphertextSubtype::Symmetric,
            Self::Asymmetric(_) => CiphertextSubtype::Asymmetric,
        }
    }
}

impl From<&OnlineCiphertextV1HeaderSymmetric> for Vec<u8> {
    /// Serialize the header into bytes
    fn from(value: &OnlineCiphertextV1HeaderSymmetric) -> Self {
        let mut buf = value.chunk_size.to_le_bytes().to_vec();
        buf.extend(value.nonce);

        buf
    }
}

impl From<&OnlineCiphertextV1HeaderAsymmetric> for Vec<u8> {
    /// Serialize the header into bytes
    fn from(value: &OnlineCiphertextV1HeaderAsymmetric) -> Self {
        let mut buf = value.chunk_size.to_le_bytes().to_vec();
        buf.extend(value.nonce);
        buf.extend_from_slice(value.public_key.as_bytes());

        buf
    }
}

impl From<&OnlineCiphertextV1Header> for Vec<u8> {
    fn from(value: &OnlineCiphertextV1Header) -> Self {
        match value {
            OnlineCiphertextV1Header::Symmetric(x) => x.into(),
            OnlineCiphertextV1Header::Asymmetric(x) => x.into(),
        }
    }
}

impl TryFrom<&[u8]> for OnlineCiphertextV1HeaderSymmetric {
    type Error = Error;

    /// Parse a header from a byte array
    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != 24 {
            return Err(Error::InvalidLength);
        }

        let (chunk_size, nonce) = value.split_at(4);

        let chunk_size: [u8; 4] = chunk_size
            .try_into()
            .expect("size is hardcoded and should always be right");
        let chunk_size = u32::from_le_bytes(chunk_size);

        let nonce = nonce
            .try_into()
            .expect("Length is checked at the start of the function");

        Ok(Self { chunk_size, nonce })
    }
}

impl TryFrom<&[u8]> for OnlineCiphertextV1HeaderAsymmetric {
    type Error = Error;

    /// Parse a header from a byte array
    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != 24 + 32 {
            return Err(Error::InvalidLength);
        }

        let (chunk_size, value) = value.split_at(4);

        let chunk_size: [u8; 4] = chunk_size
            .try_into()
            .expect("size is hardcoded and should always be right");
        let chunk_size = u32::from_le_bytes(chunk_size);

        let (nonce, public_key) = value.split_at(20);

        let nonce = nonce
            .try_into()
            .expect("size is hardcoded and should always be right");

        let public_key: [u8; 32] = public_key
            .try_into()
            .expect("size is checked at the start of the function");
        let public_key = x25519_dalek::PublicKey::from(public_key);

        Ok(Self {
            chunk_size,
            nonce,
            public_key,
        })
    }
}

/// Implements the encryptor/decryptor structure
macro_rules! online_ciphertext_impl {
    ($struct_name:ident, $cipher_name:ident, $func:ident) => {
        pub struct $struct_name {
            header: OnlineCiphertextV1Header,
            aad: Vec<u8>,
            cipher: $cipher_name<XChaCha20Poly1305>,
        }

        impl $struct_name {
            /// Gets the number of bytes to process in each chunk
            pub fn get_chunk_size(&self) -> u32 {
                self.header.get_chunk_size()
            }

            pub fn get_tag_size(&self) -> usize {
                16
            }

            pub fn get_header(&self) -> &OnlineCiphertextV1Header {
                &self.header
            }

            paste! {
                /// Process a single chunk
                pub fn [<$func _next_chunk>](
                    &mut self,
                    data: &[u8],
                    aad: &[u8],
                ) -> Result<Vec<u8>> {
                    if data.len() as u32 != self.header.get_chunk_size() && data.len() as u32 != (self.header.get_chunk_size() + self.get_tag_size() as u32){
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

                /// Process a single chunk in place.
                /// Requires a Vec because it needs to be expandable to accomodate the tag.
                pub fn  [<$func _next_chunk_in_place>](
                    &mut self,
                    data: &mut Vec<u8>,
                    aad: &[u8],
                ) -> Result<()> {
                    if data.len() as u32 != self.header.get_chunk_size() &&  data.len() as u32 != (self.header.get_chunk_size() + self.get_tag_size() as u32){
                        return Err(Error::InvalidChunkLength);
                    };

                    let mut full_aad = self.aad.to_vec();

                    if !aad.is_empty() {
                        full_aad.extend_from_slice(aad);
                    };

                    self.cipher.[<$func _next_in_place>](&full_aad, data)?;

                    Ok(())
                }

                /// Process the last chunk.
                pub fn [<$func _last_chunk>](
                    self,
                    data: &[u8],
                    aad: &[u8],
                ) -> Result<Vec<u8>> {
                    if (data.len() as u32) > (self.header.get_chunk_size() + self.get_tag_size() as u32) {
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

                /// Process a single chunk in place.
                /// Requires a Vec because it needs to be expandable to accomodate the tag.
                pub fn [<$func _last_chunk_in_place>](
                    self,
                    data: &mut Vec<u8>,
                    aad: &[u8],
                ) -> Result<()> {
                    if (data.len() as u32) > (self.header.get_chunk_size() + self.get_tag_size() as u32) {
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
    /// Creates a new encryptor and the corresponding header
    pub fn new(key: &[u8], mut aad: Vec<u8>, chunk_size: u32) -> Result<Self> {
        // Generate a new nonce
        let mut nonce = [0u8; 20];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::RandomError)?;

        // Derive the key
        let key = Zeroizing::new(blake3::derive_key(CONTEXT, key));
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());

        // Create the STREAM encryptor
        let cipher = EncryptorLE31::from_aead(cipher, &nonce.into());

        // Create aad
        let header = OnlineCiphertextV1HeaderSymmetric { chunk_size, nonce };

        let mut header_bytes: Vec<u8> = header.borrow().into();
        aad.append(&mut header_bytes);

        Ok(Self {
            header: OnlineCiphertextV1Header::Symmetric(header),
            aad,
            cipher,
        })
    }

    pub fn new_asymmetric(
        public_key: &PublicKey,
        mut aad: Vec<u8>,
        chunk_size: u32,
    ) -> Result<Self> {
        // Perform a ECDH exchange as per ECIES
        let public_key = x25519_dalek::PublicKey::from(public_key);

        let ephemeral_private_key = StaticSecret::random_from_rng(rand_08::rngs::OsRng);
        let ephemeral_public_key = x25519_dalek::PublicKey::from(&ephemeral_private_key);

        let key = ephemeral_private_key.diffie_hellman(&public_key);

        // Generate a new nonce
        let mut nonce = [0u8; 20];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::RandomError)?;

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

        Ok(Self {
            header: OnlineCiphertextV1Header::Asymmetric(header),
            cipher,
            aad,
        })
    }
}

impl OnlineCiphertextV1Decryptor {
    pub fn new(key: &[u8], mut aad: Vec<u8>, header: OnlineCiphertextV1HeaderSymmetric) -> Self {
        // Derive the key
        let key = Zeroizing::new(blake3::derive_key(CONTEXT, key));
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());

        // Create the STREAM decryptor
        let cipher = DecryptorLE31::from_aead(cipher, &header.nonce.into());

        let mut header_bytes: Vec<u8> = header.borrow().into();
        aad.append(&mut header_bytes);

        Self {
            header: OnlineCiphertextV1Header::Symmetric(header),
            aad,
            cipher,
        }
    }

    pub fn new_asymmetric(
        private_key: &PrivateKey,
        mut aad: Vec<u8>,
        header: OnlineCiphertextV1HeaderAsymmetric,
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
            header: OnlineCiphertextV1Header::Asymmetric(header),
            aad,
            cipher,
        }
    }
}

online_ciphertext_impl!(OnlineCiphertextV1Encryptor, EncryptorLE31, encrypt);
online_ciphertext_impl!(OnlineCiphertextV1Decryptor, DecryptorLE31, decrypt);
