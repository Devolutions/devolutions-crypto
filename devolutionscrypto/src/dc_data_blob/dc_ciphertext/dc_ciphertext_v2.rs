/// Ciphertext V2: XChaCha20Poly1305

use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use std::convert::TryFrom;

use aead::{
    generic_array::{typenum, GenericArray},
    Aead, NewAead, Payload,
};
use chacha20poly1305::XChaCha20Poly1305;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DcCiphertextV2 {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Into<Vec<u8>> for DcCiphertextV2 {
    fn into(mut self) -> Vec<u8> {
        let mut data = Vec::new();
        data.append(&mut self.nonce);
        data.append(&mut self.ciphertext);
        data
    }
}

impl TryFrom<&[u8]> for DcCiphertextV2 {
    type Error = DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<DcCiphertextV2> {
        if data.len() <= 24 {
            return Err(DevoCryptoError::InvalidLength);
        };

        let mut nonce = vec![0u8; 24];
        let mut ciphertext = vec![0u8; data.len() - 24];

        nonce.copy_from_slice(&data[0..24]);
        ciphertext.copy_from_slice(&data[24..]);

        Ok(DcCiphertextV2 { nonce, ciphertext })
    }
}

impl DcCiphertextV2 {
    fn derive_key(secret: &[u8]) -> GenericArray<u8, typenum::U32> {
        let mut hasher = Sha256::new();
        hasher.input(secret);
        hasher.result()
    }

    pub fn encrypt(data: &[u8], key: &[u8], header: &DcHeader) -> Result<DcCiphertextV2> {
        // Derive key
        let mut key = DcCiphertextV2::derive_key(&key);

        // Generate nonce
        let mut rng = OsRng::new()?;
        let mut nonce = vec![0u8; 24];
        rng.fill_bytes(&mut nonce);

        // Authenticate the header
        let aad: Vec<u8> = (*header).clone().into();
        let payload = Payload {
            msg: data,
            aad: &aad,
        };

        // Encrypt
        let cipher = XChaCha20Poly1305::new(key);
        let ciphertext = cipher.encrypt(&GenericArray::from_slice(&nonce), payload)?;

        // Zero out the key
        key.zeroize();

        Ok(DcCiphertextV2 { nonce, ciphertext })
    }

    pub fn decrypt(&self, key: &[u8], header: &DcHeader) -> Result<Vec<u8>> {
        // Derive key
        let mut key = DcCiphertextV2::derive_key(&key);

        // Authenticate the header
        let aad: Vec<u8> = (*header).clone().into();
        let payload = Payload {
            msg: self.ciphertext.as_slice(),
            aad: &aad,
        };

        // Decrypt
        let cipher = XChaCha20Poly1305::new(key);
        let result = cipher.decrypt(&GenericArray::from_slice(&self.nonce), payload)?;

        // Zeroize the key
        key.zeroize();

        Ok(result)
    }
}
