mod dc_ciphertext_v1;

use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use self::dc_ciphertext_v1::DcCiphertextV1;

use std::convert::TryFrom as _;

pub const CIPHERTEXT: u16 = 2;

const V1: u16 = 1;

pub enum DcCiphertext {
    V1(DcCiphertextV1),
}

impl DcCiphertext {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcCiphertext> {
        match header.version {
            V1 => Ok(DcCiphertext::V1(DcCiphertextV1::try_from(data)?)),
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }

    pub fn encrypt(data: &[u8], key: &[u8], header: &mut DcHeader) -> Result<DcCiphertext> {
        header.data_type = CIPHERTEXT;
        header.version = V1;

        Ok(DcCiphertext::V1(DcCiphertextV1::encrypt(
            data, key, header,
        )?))
    }

    pub fn decrypt(&self, key: &[u8], header: &DcHeader) -> Result<Vec<u8>> {
        match self {
            DcCiphertext::V1(x) => x.decrypt(key, header),
        }
    }
}

impl Into<Vec<u8>> for DcCiphertext {
    fn into(self) -> Vec<u8> {
        match self {
            DcCiphertext::V1(x) => x.into(),
        }
    }
}