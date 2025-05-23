//! Ciphertext V1: AES256-CBC with HMAC-SHA256
use super::Error;
use super::Header;
use super::Result;

use super::Ciphertext;

use std::convert::TryFrom;

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use rand::TryRngCore;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[derive(Zeroize, Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[zeroize(drop)]
pub struct CiphertextV1 {
    iv: [u8; 16],
    ciphertext: Vec<u8>,
    hmac: [u8; 32],
}

impl From<CiphertextV1> for Vec<u8> {
    fn from(mut cipher: CiphertextV1) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&cipher.iv);
        data.append(&mut cipher.ciphertext);
        data.extend_from_slice(&cipher.hmac);
        data
    }
}

impl TryFrom<&[u8]> for CiphertextV1 {
    type Error = Error;
    fn try_from(data: &[u8]) -> Result<CiphertextV1> {
        if data.len() <= 48 {
            return Err(Error::InvalidLength);
        };

        let mut iv = [0u8; 16];
        let mut ciphertext = vec![0u8; data.len() - 16 - 32];
        let mut hmac = [0u8; 32];

        iv.copy_from_slice(&data[0..16]);
        ciphertext.copy_from_slice(&data[16..data.len() - 32]);
        hmac.copy_from_slice(&data[data.len() - 32..]);

        Ok(CiphertextV1 {
            iv,
            ciphertext,
            hmac,
        })
    }
}

impl CiphertextV1 {
    fn split_key(secret: &[u8], encryption_key: &mut [u8], signature_key: &mut [u8]) -> Result<()> {
        let salt = b"\x00";
        pbkdf2::<Hmac<Sha256>>(secret, &salt[0..1], 1, encryption_key)?;

        let salt = b"\x01";
        pbkdf2::<Hmac<Sha256>>(secret, &salt[0..1], 1, signature_key)?;

        Ok(())
    }

    pub fn encrypt(
        data: &[u8],
        key: &[u8],
        aad: &[u8],
        header: &Header<Ciphertext>,
    ) -> Result<CiphertextV1> {
        // Split keys
        let mut encryption_key = Zeroizing::new(vec![0u8; 32]);
        let mut signature_key = Zeroizing::new(vec![0u8; 32]);
        CiphertextV1::split_key(key, &mut encryption_key, &mut signature_key)?;

        // Generate IV
        let mut iv = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut iv)
            .map_err(|_| Error::RandomError)?;

        // Create cipher object
        let cipher = cbc::Encryptor::<Aes256>::new_from_slices(&encryption_key, &iv)?;
        let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(data);

        // Append MAC data
        let mut mac_data: Zeroizing<Vec<u8>> = Zeroizing::new(header.into());
        mac_data.extend_from_slice(aad);
        mac_data.extend_from_slice(&iv);
        mac_data.extend_from_slice(&ciphertext);

        // HMAC
        let mut mac = Hmac::<Sha256>::new_from_slice(&signature_key)?;
        mac.update(&mac_data);

        let hmac: [u8; 32] = mac.finalize().into_bytes().into();

        Ok(CiphertextV1 {
            iv,
            ciphertext,
            hmac,
        })
    }

    pub fn decrypt(&self, key: &[u8], aad: &[u8], header: &Header<Ciphertext>) -> Result<Vec<u8>> {
        // Split keys
        let mut encryption_key = Zeroizing::new(vec![0u8; 32]);
        let mut signature_key = Zeroizing::new(vec![0u8; 32]);
        CiphertextV1::split_key(key, &mut encryption_key, &mut signature_key)?;

        // Verify HMAC
        let mut mac_data: Zeroizing<Vec<u8>> = Zeroizing::new(header.into());
        mac_data.extend_from_slice(aad);
        mac_data.extend_from_slice(&self.iv);
        mac_data.extend_from_slice(&self.ciphertext);

        let mut mac = Hmac::<Sha256>::new_from_slice(&signature_key)?;
        mac.update(&mac_data);
        mac.verify_slice(&self.hmac)?;

        let cipher = cbc::Decryptor::<Aes256>::new_from_slices(&encryption_key, &self.iv)?;
        let result = cipher.decrypt_padded_vec_mut::<Pkcs7>(&self.ciphertext)?;

        Ok(result)
    }
}
