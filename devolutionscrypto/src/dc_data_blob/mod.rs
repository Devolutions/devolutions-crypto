use std;
use std::convert::TryFrom;

use super::Result;
use super::DevoCryptoError;

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
    Key(DcKey),
    Ciphertext(DcCiphertext),
    Hash(DcHash),
}

impl TryFrom<&[u8]> for DcDataBlob {
    type Error = DevoCryptoError;
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
                Ok(DcPayload::Key(DcKey::try_from_header(data, header)?))
            }
            CIPHERTEXT => {
                Ok(DcPayload::Ciphertext(DcCiphertext::try_from_header(data, header)?))
            }
            HASH => {
                Ok(DcPayload::Hash(DcHash::try_from_header(data, header)?))
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
    fn into(self) -> Vec<u8> {
        match self {
            DcPayload::Key(x) => x.into(),
            DcPayload::Ciphertext(x) => x.into(),
            DcPayload::Hash(x) => x.into(),
        }
    }
}
