use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use std::convert::TryFrom;

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DcCiphertextV1 {
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    hmac: Vec<u8>,
}

impl Into<Vec<u8>> for DcCiphertextV1 {
    fn into(mut self) -> Vec<u8> {
        let mut data = Vec::new();
        data.append(&mut self.iv);
        data.append(&mut self.ciphertext);
        data.append(&mut self.hmac);
        data
    }
}

impl TryFrom<&[u8]> for DcCiphertextV1 {
    type Error = DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<DcCiphertextV1> {
        if data.len() <= 48 {
            return Err(DevoCryptoError::InvalidLength);
        };

        let mut iv = vec![0u8; 16];
        let mut ciphertext = vec![0u8; data.len() - 16 - 32];
        let mut hmac = vec![0u8; 32];

        iv.copy_from_slice(&data[0..16]);
        ciphertext.copy_from_slice(&data[16..data.len() - 32]);
        hmac.copy_from_slice(&data[data.len() - 32..]);

        Ok(DcCiphertextV1 {
            iv,
            ciphertext,
            hmac,
        })
    }
}

impl DcCiphertextV1 {
    fn split_key(secret: &[u8], encryption_key: &mut [u8], signature_key: &mut [u8]) {
        let salt = b"\x00";
        pbkdf2::<Hmac<Sha256>>(secret, &salt[0..1], 1, encryption_key);

        let salt = b"\x01";
        pbkdf2::<Hmac<Sha256>>(secret, &salt[0..1], 1, signature_key);
    }

    #[allow(dead_code)]
    pub fn encrypt(data: &[u8], key: &[u8], header: &DcHeader) -> Result<DcCiphertextV1> {
        // Split keys
        let mut encryption_key = vec![0u8; 32];
        let mut signature_key = vec![0u8; 32];
        DcCiphertextV1::split_key(key, &mut encryption_key, &mut signature_key);

        // Generate IV
        let mut rng = OsRng::new()?;
        let mut iv = vec![0u8; 16];
        rng.fill_bytes(&mut iv);

        // Create cipher object
        let cipher = Cbc::<Aes256, Pkcs7>::new_var(&encryption_key, &iv)?;
        let ciphertext = cipher.encrypt_vec(data);

        // Zero out the key
        encryption_key.zeroize();

        // Append MAC data
        let mut mac_data: Vec<u8> = (*header).clone().into();
        mac_data.append(&mut iv.clone());
        mac_data.append(&mut ciphertext.clone());

        // HMAC
        let mut mac = Hmac::<Sha256>::new_varkey(&signature_key)?;
        mac.input(&mac_data);

        let hmac = mac.result().code().to_vec();

        // Zero out the key
        signature_key.zeroize();

        Ok(DcCiphertextV1 {
            iv,
            ciphertext,
            hmac,
        })
    }

    pub fn decrypt(&self, key: &[u8], header: &DcHeader) -> Result<Vec<u8>> {
        // Split keys
        let mut encryption_key = vec![0u8; 32];
        let mut signature_key = vec![0u8; 32];
        DcCiphertextV1::split_key(key, &mut encryption_key, &mut signature_key);

        // Verify HMAC
        let mut mac_data: Vec<u8> = (*header).clone().into();
        mac_data.append(&mut self.iv.clone());
        mac_data.append(&mut self.ciphertext.clone());

        let mut mac = Hmac::<Sha256>::new_varkey(&signature_key)?;
        mac.input(&mac_data);
        mac.verify(&self.hmac)?;

        // Zeroize the key
        signature_key.zeroize();
        mac_data.zeroize();

        let cipher = Cbc::<Aes256, Pkcs7>::new_var(&encryption_key, &self.iv)?;
        let result = cipher.decrypt_vec(&self.ciphertext)?;

        // Zeroize the key
        encryption_key.zeroize();

        Ok(result)
    }
}
