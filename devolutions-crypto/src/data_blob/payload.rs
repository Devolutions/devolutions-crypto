use super::DevoCryptoError;
use super::Result;

use super::DcHeader;

use super::{DcCiphertext, CIPHERTEXT};
use super::{DcPasswordHash, PASSWORD_HASH};
use super::{DcKey, KEY};
use super::{DcChecksum, CHECKSUM};

pub enum DcPayload {
    Key(DcKey),
    Ciphertext(DcCiphertext),
    PasswordHash(DcPasswordHash),
    Checksum(DcChecksum),
}

impl DcPayload {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcPayload> {
        match header.data_type {
            KEY => Ok(DcPayload::Key(DcKey::try_from_header(data, header)?)),
            CIPHERTEXT => Ok(DcPayload::Ciphertext(DcCiphertext::try_from_header(
                data, header,
            )?)),
            PASSWORD_HASH => Ok(DcPayload::PasswordHash(DcPasswordHash::try_from_header(data, header)?)),
            CHECKSUM => Ok(DcPayload::Checksum(DcChecksum::try_from_header(data, header)?)),
            _ => Err(DevoCryptoError::UnknownType),
        }
    }

    pub fn encrypt(
        data: &[u8],
        key: &[u8],
        header: &mut DcHeader,
        version: Option<u16>,
    ) -> Result<DcPayload> {
        Ok(DcPayload::Ciphertext(DcCiphertext::encrypt(
            data, key, header, version,
        )?))
    }

    pub fn decrypt(&self, key: &[u8], header: &DcHeader) -> Result<Vec<u8>> {
        match self {
            DcPayload::Ciphertext(x) => x.decrypt(key, header),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }

    pub fn hash_password(pass: &[u8], iterations: u32, header: &mut DcHeader) -> Result<DcPayload> {
        Ok(DcPayload::PasswordHash(DcPasswordHash::hash_password(
            pass, iterations, header,
        )?))
    }

    pub fn validate(&self, data: &[u8]) -> Result<bool> {
        match self {
            DcPayload::PasswordHash(x) => x.verify_password(data),
            DcPayload::Checksum(x) => x.validate_checksum(data),
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

    pub fn checksum(
        data: &[u8],
        header: &mut DcHeader,
        version: Option<u16>,
    ) -> Result<DcPayload> {
        Ok(DcPayload::Checksum(DcChecksum::checksum(
            data, header, version,
        )?))
    }
}

impl From<DcPayload> for Vec<u8> {
    fn from(payload: DcPayload) -> Vec<u8> {
        match payload {
            DcPayload::Key(x) => x.into(),
            DcPayload::Ciphertext(x) => x.into(),
            DcPayload::PasswordHash(x) => x.into(),
            DcPayload::Checksum(x) => x.into(),
        }
    }
}
