use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std;
use std::convert::TryFrom;
use std::io::Cursor;

use super::Result;

mod dc_ciphertext;
mod dc_hash;
mod dc_key;

use self::dc_ciphertext::DcCiphertext;
use self::dc_hash::DcHash;
use self::dc_key::DcKey;

const KEY: u16 = 1;
const CIPHERTEXT: u16 = 2;
const HASH: u16 = 3;

pub struct DcDataBlob {
    header: DcHeader,
    payload: DcPayload,
}

pub struct DcHeader {
    signature: u16,
    data_type: u16,
    data_subtype: u16,
    version: u16,
}

pub enum DcPayload {
    Key(DcKey),
    Ciphertext(DcCiphertext),
    Hash(DcHash),
}

impl TryFrom<&[u8]> for DcDataBlob {
    type Error = super::devocrypto_errors::DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<DcDataBlob> {
        let header = DcHeader::try_from(&data[0..8])?;
        let payload = DcPayload::try_from_header(&data[8..], &header)?;
        Ok(DcDataBlob { header, payload })
    }
}

impl TryFrom<&[u8]> for DcHeader {
    type Error = super::devocrypto_errors::DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<DcHeader> {
        let mut data_cursor = Cursor::new(data);
        let signature = data_cursor.read_u16::<LittleEndian>()?;
        let data_type = data_cursor.read_u16::<LittleEndian>()?;
        let data_subtype = data_cursor.read_u16::<LittleEndian>()?;
        let version = data_cursor.read_u16::<LittleEndian>()?;

        Ok(DcHeader {
            signature,
            data_type,
            data_subtype,
            version,
        })
    }
}

impl DcPayload {
    fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcPayload> {
        match header.data_type {
            KEY => {
                let key = DcKey::try_from_header(data, header)?;
                Ok(DcPayload::Key(key))
            }
            CIPHERTEXT => {
                let ciphertext = DcCiphertext::try_from_header(data, header)?;
                Ok(DcPayload::Ciphertext(ciphertext))
            }
            HASH => {
                let hash = DcHash::try_from_header(data, header)?;
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

impl Into<Vec<u8>> for DcHeader {
    fn into(self) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        data.write_u16::<LittleEndian>(self.signature);
        data.write_u16::<LittleEndian>(self.data_type);
        data.write_u16::<LittleEndian>(self.data_subtype);
        data.write_u16::<LittleEndian>(self.version);
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
