use std;
use std::convert::TryFrom;

use super::DevoCryptoError;
use super::Result;

mod dc_header;
mod dc_payload;

mod dc_ciphertext;
mod dc_hash;
mod dc_key;

pub use self::dc_header::DcHeader;
pub use self::dc_payload::DcPayload;

pub use self::dc_ciphertext::{DcCiphertext, CIPHERTEXT};
pub use self::dc_hash::{DcHash, HASH};
pub use self::dc_key::{DcKey, KEY};

pub struct DcDataBlob {
    header: DcHeader,
    payload: DcPayload,
}

impl TryFrom<&[u8]> for DcDataBlob {
    type Error = DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<DcDataBlob> {
        let header = DcHeader::try_from(&data[0..8])?;
        let payload = DcPayload::try_from_header(&data[8..], &header)?;
        Ok(DcDataBlob { header, payload })
    }
}

impl Into<Vec<u8>> for DcDataBlob {
    fn into(self) -> Vec<u8> {
        let mut data: Vec<u8> = self.header.into();
        let mut payload: Vec<u8> = self.payload.into();
        data.append(&mut payload);
        data
    }
}

impl DcDataBlob {
    pub fn encrypt(data: &[u8], key: &[u8]) -> Result<DcDataBlob> {
        let mut header = DcHeader::new();
        let payload = DcPayload::encrypt(data, key, &mut header)?;
        Ok(DcDataBlob { header, payload })
    }

    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>> {
        self.payload.decrypt(key, &self.header)
    }

    pub fn hash_password(pass: &[u8], iterations: u32) -> Result<DcDataBlob> {
        let mut header = DcHeader::new();
        let payload = DcPayload::hash_password(pass, iterations, &mut header)?;
        Ok(DcDataBlob { header, payload })
    }

    pub fn verify_password(&self, pass: &[u8]) -> Result<bool> {
        self.payload.verify_password(pass)
    }
}
