use super::DataType;

use super::DevoCryptoError;
use super::Result;

use std::convert::TryFrom;
use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use zeroize::Zeroize;

const SIGNATURE: u16 = 0x0C0D;

#[derive(Clone)]
pub struct Header<S, V>
where
    S: Clone + Default,
    V: Clone + Default,
{
    pub signature: u16,
    pub data_type: DataType,
    pub data_subtype: S,
    pub version: V,
}

impl<S, V> TryFrom<&[u8]> for Header<S, V>
where
    S: Into<u16> + TryFrom<u16> + Clone + Zeroize + Default,
    V: Into<u16> + TryFrom<u16> + Clone + Zeroize + Default,
{
    type Error = crate::error::DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<Self> {
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

        let data_subtype = match S::try_from(data_subtype) {
            Ok(d) => d,
            Err(_) => return Err(DevoCryptoError::UnknownSubtype),
        };

        let version = match V::try_from(version) {
            Ok(d) => d,
            Err(_) => return Err(DevoCryptoError::UnknownVersion),
        };

        Ok(Header {
            signature,
            data_type,
            data_subtype,
            version,
        })
    }
}

impl<S, V> From<Header<S, V>> for Vec<u8>
where
    S: Into<u16> + TryFrom<u16> + Clone + Zeroize + Default,
    V: Into<u16> + TryFrom<u16> + Clone + Zeroize + Default,
{
    fn from(header: Header<S, V>) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        data.write_u16::<LittleEndian>(header.signature).unwrap();
        data.write_u16::<LittleEndian>(header.data_type.into())
            .unwrap();
        data.write_u16::<LittleEndian>(header.data_subtype.into())
            .unwrap();
        data.write_u16::<LittleEndian>(header.version.into())
            .unwrap();
        data
    }
}

impl<S, V> Default for Header<S, V>
where
    S: Into<u16> + TryFrom<u16> + Clone + Zeroize + Default,
    V: Into<u16> + TryFrom<u16> + Clone + Zeroize + Default,
{
    fn default() -> Self {
        Header {
            signature: SIGNATURE,
            data_type: DataType::None,
            data_subtype: S::default(),
            version: V::default(),
        }
    }
}

impl Header<(), ()> {
    pub fn len() -> usize {
        8
    }
}
