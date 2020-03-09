/// Ciphertext V2: XChaCha20Poly1305
use crate::DcDataBlob;

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
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const SYMMETRIC: u16 = 1;
const ASYMMETRIC: u16 = 2;

#[derive(Clone)]
pub enum DcCiphertextV2 {
    Symmetric(DcCiphertextV2Symmetric),
    Asymmetric(DcCiphertextV2Asymmetric),
}

#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct DcCiphertextV2Symmetric {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Clone)]
pub struct DcCiphertextV2Asymmetric {
    public_key: PublicKey,
    ciphertext: DcCiphertextV2Symmetric,
}

impl From<DcCiphertextV2Symmetric> for Vec<u8> {
    fn from(mut cipher: DcCiphertextV2Symmetric) -> Vec<u8> {
        let mut data = Vec::new();
        data.append(&mut cipher.nonce);
        data.append(&mut cipher.ciphertext);
        data
    }
}

impl From<DcCiphertextV2> for Vec<u8> {
    fn from(ciphertext: DcCiphertextV2) -> Self {
        match ciphertext {
            DcCiphertextV2::Symmetric(c) => c.into(),
            DcCiphertextV2::Asymmetric(c) => c.into(),
        }
    }
}

impl DcCiphertextV2 {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<Self> {
        Ok(match header.data_subtype {
            0 | SYMMETRIC => Self::Symmetric(DcCiphertextV2Symmetric::try_from(data)?),
            ASYMMETRIC => Self::Asymmetric(DcCiphertextV2Asymmetric::try_from(data)?),
            _ => return Err(DevoCryptoError::UnknownSubtype),
        })
    }

    pub fn encrypt(data: &[u8], key: &[u8], header: &mut DcHeader) -> Result<Self> {
        header.data_subtype = SYMMETRIC;

        Ok(Self::Symmetric(DcCiphertextV2Symmetric::encrypt(
            data, key, header,
        )?))
    }

    pub fn encrypt_asymmetric(
        data: &[u8],
        public_key: &DcDataBlob,
        header: &mut DcHeader,
    ) -> Result<Self> {
        header.data_subtype = ASYMMETRIC;

        Ok(Self::Asymmetric(DcCiphertextV2Asymmetric::encrypt(
            data, public_key, header,
        )?))
    }

    pub fn decrypt(&self, key: &[u8], header: &DcHeader) -> Result<Vec<u8>> {
        match self {
            Self::Symmetric(c) => c.decrypt(key, header),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }

    pub fn decrypt_asymmetric(
        &self,
        private_key: &DcDataBlob,
        header: &DcHeader,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Asymmetric(c) => c.decrypt(private_key, header),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }
}

impl TryFrom<&[u8]> for DcCiphertextV2Symmetric {
    type Error = DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() <= 24 {
            return Err(DevoCryptoError::InvalidLength);
        };

        let mut nonce = vec![0u8; 24];
        let mut ciphertext = vec![0u8; data.len() - 24];

        nonce.copy_from_slice(&data[0..24]);
        ciphertext.copy_from_slice(&data[24..]);

        Ok(DcCiphertextV2Symmetric { nonce, ciphertext })
    }
}

impl DcCiphertextV2Symmetric {
    fn derive_key(secret: &[u8]) -> GenericArray<u8, typenum::U32> {
        let mut hasher = Sha256::new();
        hasher.input(secret);
        hasher.result()
    }

    pub fn encrypt(data: &[u8], key: &[u8], header: &DcHeader) -> Result<Self> {
        // Derive key
        let mut key = DcCiphertextV2Symmetric::derive_key(&key);

        // Generate nonce
        let mut nonce = vec![0u8; 24];
        OsRng.fill_bytes(&mut nonce);

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

        Ok(DcCiphertextV2Symmetric { nonce, ciphertext })
    }

    pub fn decrypt(&self, key: &[u8], header: &DcHeader) -> Result<Vec<u8>> {
        // Derive key
        let mut key = DcCiphertextV2Symmetric::derive_key(&key);

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

impl From<DcCiphertextV2Asymmetric> for Vec<u8> {
    fn from(cipher: DcCiphertextV2Asymmetric) -> Self {
        let mut data = Vec::new();
        let mut public_key = cipher.public_key.as_bytes().to_vec();
        let mut ciphertext = cipher.ciphertext.into();
        data.append(&mut public_key);
        data.append(&mut ciphertext);
        data
    }
}

impl TryFrom<&[u8]> for DcCiphertextV2Asymmetric {
    type Error = DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() <= 32 {
            return Err(DevoCryptoError::InvalidLength);
        };

        let mut public_key = [0u8; 32];

        public_key.copy_from_slice(&data[0..32]);
        let ciphertext = DcCiphertextV2Symmetric::try_from(&data[32..])?;

        Ok(DcCiphertextV2Asymmetric {
            public_key: PublicKey::from(public_key),
            ciphertext,
        })
    }
}

impl DcCiphertextV2Asymmetric {
    pub fn encrypt(data: &[u8], public_key: &DcDataBlob, header: &DcHeader) -> Result<Self> {
        let public_key = PublicKey::try_from(public_key)?;

        let ephemeral_private_key = StaticSecret::new(&mut OsRng);
        let ephemeral_public_key = PublicKey::from(&ephemeral_private_key);

        let key = ephemeral_private_key.diffie_hellman(&public_key);

        let ciphertext = DcCiphertextV2Symmetric::encrypt(data, key.as_bytes(), header)?;

        Ok(Self {
            public_key: ephemeral_public_key,
            ciphertext,
        })
    }

    pub fn decrypt(&self, private_key: &DcDataBlob, header: &DcHeader) -> Result<Vec<u8>> {
        let private_key = StaticSecret::try_from(private_key)?;

        let key = private_key.diffie_hellman(&self.public_key);

        self.ciphertext.decrypt(key.as_bytes(), header)
    }
}
