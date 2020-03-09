use super::DataType;

use super::DevoCryptoError;
use super::Result;

use std::convert::TryFrom;
use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use zeroize::Zeroize;

const SIGNATURE: u16 = 0x0C0D;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DcHeader {
    pub signature: u16,
    pub data_type: DataType,
    pub data_subtype: u16,
    pub version: u16,
}

impl TryFrom<&[u8]> for DcHeader {
    type Error = crate::error::DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<DcHeader> {
        let mut data_cursor = Cursor::new(data);
        let signature = data_cursor.read_u16::<LittleEndian>()?;
        let data_type = data_cursor.read_u16::<LittleEndian>()?;
        let data_subtype = data_cursor.read_u16::<LittleEndian>()?;
        let version = data_cursor.read_u16::<LittleEndian>()?;

        if signature != SIGNATURE {
            return Err(DevoCryptoError::InvalidSignature);
        }

        let data_type = match DataType::try_from(data_type) {
            Ok(d) => d,
            Err(_) => return Err(DevoCryptoError::UnknownType),
        };

        Ok(DcHeader {
            signature,
            data_type,
            data_subtype,
            version,
        })
    }
}

impl From<DcHeader> for Vec<u8> {
    fn from(header: DcHeader) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        data.write_u16::<LittleEndian>(header.signature).unwrap();
        data.write_u16::<LittleEndian>(header.data_type.into())
            .unwrap();
        data.write_u16::<LittleEndian>(header.data_subtype).unwrap();
        data.write_u16::<LittleEndian>(header.version).unwrap();
        data
    }
}

impl Default for DcHeader {
    fn default() -> Self {
        DcHeader {
            signature: SIGNATURE,
            data_type: DataType::None,
            data_subtype: 0,
            version: 0,
        }
    }
}

impl DcHeader {
    pub fn len() -> usize {
        8
    }
}
