mod ciphertext_v1;
mod ciphertext_v2;

use crate::DcDataBlob;

use super::DataType;
use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use self::ciphertext_v1::DcCiphertextV1;
use self::ciphertext_v2::DcCiphertextV2;

use std::convert::TryFrom as _;

const V1: u16 = 1;
const V2: u16 = 2;

#[derive(Clone)]
pub enum DcCiphertext {
    V1(DcCiphertextV1),
    V2(DcCiphertextV2),
}

impl DcCiphertext {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcCiphertext> {
        match header.version {
            V1 => Ok(DcCiphertext::V1(DcCiphertextV1::try_from(data)?)),
            V2 => Ok(DcCiphertext::V2(DcCiphertextV2::try_from_header(
                data, header,
            )?)),
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }

    pub fn encrypt(
        data: &[u8],
        key: &[u8],
        header: &mut DcHeader,
        version: Option<u16>,
    ) -> Result<DcCiphertext> {
        header.data_type = DataType::Ciphertext;

        match version {
            Some(V1) => {
                header.version = V1;
                Ok(DcCiphertext::V1(DcCiphertextV1::encrypt(
                    data, key, header,
                )?))
            }
            Some(V2) | None => {
                header.version = V2;
                Ok(DcCiphertext::V2(DcCiphertextV2::encrypt(
                    data, key, header,
                )?))
            }
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }

    pub fn encrypt_asymmetric(
        data: &[u8],
        public_key: &DcDataBlob,
        header: &mut DcHeader,
        version: Option<u16>,
    ) -> Result<DcCiphertext> {
        header.data_type = DataType::Ciphertext;

        match version {
            Some(V2) | None => {
                header.version = V2;
                Ok(DcCiphertext::V2(DcCiphertextV2::encrypt_asymmetric(
                    data, public_key, header,
                )?))
            }
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }

    pub fn decrypt(&self, key: &[u8], header: &DcHeader) -> Result<Vec<u8>> {
        match self {
            DcCiphertext::V1(x) => x.decrypt(key, header),
            DcCiphertext::V2(x) => x.decrypt(key, header),
        }
    }

    pub fn decrypt_asymmetric(
        &self,
        private_key: &DcDataBlob,
        header: &DcHeader,
    ) -> Result<Vec<u8>> {
        match self {
            DcCiphertext::V2(x) => x.decrypt_asymmetric(private_key, header),
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }
}

impl From<DcCiphertext> for Vec<u8> {
    fn from(cipher: DcCiphertext) -> Vec<u8> {
        match cipher {
            DcCiphertext::V1(x) => x.into(),
            DcCiphertext::V2(x) => x.into(),
        }
    }
}
