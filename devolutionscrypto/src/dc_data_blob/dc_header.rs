use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::Cursor;

use super::DevoCryptoError;
use super::Result;

const SIGNATURE: u16 = 0x0C0D;

#[derive(Clone)]
pub struct DcHeader {
    pub signature: u16,
    pub data_type: u16,
    pub data_subtype: u16,
    pub version: u16,
}

impl TryFrom<&[u8]> for DcHeader {
    type Error = super::super::devocrypto_errors::DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<DcHeader> {
        let mut data_cursor = Cursor::new(data);
        let signature = data_cursor.read_u16::<LittleEndian>()?;
        let data_type = data_cursor.read_u16::<LittleEndian>()?;
        let data_subtype = data_cursor.read_u16::<LittleEndian>()?;
        let version = data_cursor.read_u16::<LittleEndian>()?;

        if signature != SIGNATURE {
            return Err(DevoCryptoError::InvalidSignature);
        }

        Ok(DcHeader {
            signature,
            data_type,
            data_subtype,
            version,
        })
    }
}

impl Into<Vec<u8>> for DcHeader {
    fn into(self) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        data.write_u16::<LittleEndian>(self.signature).unwrap();
        data.write_u16::<LittleEndian>(self.data_type).unwrap();
        data.write_u16::<LittleEndian>(self.data_subtype).unwrap();
        data.write_u16::<LittleEndian>(self.version).unwrap();
        data
    }
}

impl DcHeader {
    pub fn new() -> DcHeader {
        DcHeader {
            signature: SIGNATURE,
            data_type: 0,
            data_subtype: 0,
            version: 0,
        }
    }
}
