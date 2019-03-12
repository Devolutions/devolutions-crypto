use super::DevoCryptoError;
use super::Result;

use super::DcHeader;

use super::{DcCiphertext, CIPHERTEXT};
use super::{DcHash, HASH};
use super::{DcKey, KEY};

pub enum DcPayload {
    Key(DcKey),
    Ciphertext(DcCiphertext),
    Hash(DcHash),
}

impl DcPayload {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcPayload> {
        match header.data_type {
            KEY => Ok(DcPayload::Key(DcKey::try_from_header(data, header)?)),
            CIPHERTEXT => Ok(DcPayload::Ciphertext(DcCiphertext::try_from_header(
                data, header,
            )?)),
            HASH => Ok(DcPayload::Hash(DcHash::try_from_header(data, header)?)),
            _ => Err(DevoCryptoError::UnknownType),
        }
    }

    pub fn encrypt(data: &[u8], key: &[u8], header: &mut DcHeader) -> Result<DcPayload> {
        Ok(DcPayload::Ciphertext(DcCiphertext::encrypt(
            data, key, header,
        )?))
    }

    pub fn decrypt(&self, key: &[u8], header: &DcHeader) -> Result<Vec<u8>> {
        match self {
            DcPayload::Ciphertext(x) => x.decrypt(key, header),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }

    pub fn hash_password(pass: &[u8], iterations: u32, header: &mut DcHeader) -> Result<DcPayload> {
        Ok(DcPayload::Hash(DcHash::hash_password(
            pass, iterations, header,
        )?))
    }

    pub fn verify_password(&self, pass: &[u8]) -> Result<bool> {
        match self {
            DcPayload::Hash(x) => x.verify_password(pass),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }

    pub fn generate_key_exchange(
        header_private: &mut DcHeader,
        header_public: &mut DcHeader,
    ) -> Result<(DcPayload, DcPayload)> {
        let (private_key, public_key) =
            DcKey::generate_key_exchange(header_private, header_public)?;
        Ok((DcPayload::Key(private_key), DcPayload::Key(public_key)))
    }

    pub fn mix_key_exchange(self, public: DcPayload) -> Result<Vec<u8>> {
        match (self, public) {
            (DcPayload::Key(private), DcPayload::Key(public)) => private.mix_key_exchange(public),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }
}

impl Into<Vec<u8>> for DcPayload {
    fn into(self) -> Vec<u8> {
        match self {
            DcPayload::Key(x) => x.into(),
            DcPayload::Ciphertext(x) => x.into(),
            DcPayload::Hash(x) => x.into(),
        }
    }
}
