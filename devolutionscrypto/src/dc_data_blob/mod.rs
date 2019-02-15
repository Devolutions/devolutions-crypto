use std;
use std::convert::TryFrom;

use super::Result;

use super::hash_from_version;
use super::HashImpl;

mod dc_ciphertext;
mod dc_hash;
mod dc_header;
mod dc_key;

pub use self::dc_ciphertext::DcCiphertext;
pub use self::dc_hash::DcHash;
pub use self::dc_header::DcHeader;
pub use self::dc_key::DcKey;

const KEY: u16 = 1;
const CIPHERTEXT: u16 = 2;
const HASH: u16 = 3;

pub struct DcDataBlob {
    header: DcHeader,
    payload: DcPayload,
}

pub enum DcPayload {
    Key(Box<HashImpl>),
    Ciphertext(Box<HashImpl>),
    Hash(Box<HashImpl>),
}

impl TryFrom<&[u8]> for DcDataBlob {
    type Error = super::devocrypto_errors::DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<DcDataBlob> {
        let header = DcHeader::try_from(&data[0..8])?;
        let payload = DcPayload::try_from_header(&data[8..], &header)?;
        Ok(DcDataBlob { header, payload })
    }
}

impl DcPayload {
    fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcPayload> {
        match header.data_type {
            KEY => {
                let hash = hash_from_version(data, header)?;
                Ok(DcPayload::Hash(hash))
            }
            CIPHERTEXT => {
                let hash = hash_from_version(data, header)?;
                Ok(DcPayload::Hash(hash))
            }
            HASH => {
                let hash = hash_from_version(data, header)?;
                Ok(DcPayload::Hash(hash))
            }
            _ => panic!(),
        }
    }

    fn payload_type(&self) -> u16 {
        match self {
            DcPayload::Key(_) => KEY,
            DcPayload::Ciphertext(_) => CIPHERTEXT,
            DcPayload::Hash(_) => HASH,
        }
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

impl Into<Vec<u8>> for DcPayload {
    fn into(mut self) -> Vec<u8> {
        match self {
            DcPayload::Key(ref mut x) => x.into_vec(),
            DcPayload::Ciphertext(ref mut x) => x.into_vec(),
            DcPayload::Hash(ref mut x) => x.into_vec(),
        }
    }
}
