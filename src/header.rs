use super::DataType;

use super::Error;
use super::Result;

use cfg_if::cfg_if;
use std::convert::TryFrom;
use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use zeroize::Zeroize;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

const SIGNATURE: u16 = 0x0C0D;

pub trait HeaderType {
    cfg_if! {
        if #[cfg(feature = "fuzz")] {
            type Version: Into<u16> + TryFrom<u16> + Clone + Default + Zeroize + std::fmt::Debug + Arbitrary;
            type Subtype: Into<u16> + TryFrom<u16> + Clone + Default + Zeroize + std::fmt::Debug + Arbitrary;
        }
        else {
            type Version: Into<u16> + TryFrom<u16> + Clone + Default + Zeroize + std::fmt::Debug;
            type Subtype: Into<u16> + TryFrom<u16> + Clone + Default + Zeroize + std::fmt::Debug;
        }
    }

    fn data_type() -> DataType;

    fn default_version() -> Self::Version {
        Default::default()
    }

    fn subtype() -> Self::Subtype {
        Default::default()
    }
}

// Default values, used for len()
impl HeaderType for () {
    type Version = super::CiphertextVersion;
    type Subtype = super::CiphertextSubtype;

    fn data_type() -> DataType {
        super::DataType::None
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct Header<M>
where
    M: HeaderType,
{
    pub signature: u16,
    pub data_type: DataType,
    pub data_subtype: M::Subtype,
    pub version: M::Version,
}

impl<M> TryFrom<&[u8]> for Header<M>
where
    M: HeaderType,
{
    type Error = crate::error::Error;
    fn try_from(data: &[u8]) -> Result<Self> {
        let mut data_cursor = Cursor::new(data);
        let signature = data_cursor.read_u16::<LittleEndian>()?;
        let data_type = data_cursor.read_u16::<LittleEndian>()?;
        let data_subtype = data_cursor.read_u16::<LittleEndian>()?;
        let version = data_cursor.read_u16::<LittleEndian>()?;

        if signature != SIGNATURE {
            return Err(Error::InvalidSignature);
        }

        let data_type = match DataType::try_from(data_type) {
            Ok(d) => d,
            Err(_) => return Err(Error::UnknownType),
        };

        let data_subtype = match M::Subtype::try_from(data_subtype) {
            Ok(d) => d,
            Err(_) => return Err(Error::UnknownSubtype),
        };

        let version = match M::Version::try_from(version) {
            Ok(d) => d,
            Err(_) => return Err(Error::UnknownVersion),
        };

        if data_type != M::data_type() {
            return Err(Error::InvalidData);
        };

        Ok(Header {
            signature,
            data_type,
            data_subtype,
            version,
        })
    }
}

impl<M> From<Header<M>> for Vec<u8>
where
    M: HeaderType,
{
    fn from(header: Header<M>) -> Vec<u8> {
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

impl<M> Default for Header<M>
where
    M: HeaderType,
{
    fn default() -> Self {
        Header {
            signature: SIGNATURE,
            data_type: M::data_type(),
            data_subtype: M::subtype(),
            version: M::default_version(),
        }
    }
}

impl Header<()> {
    pub fn len() -> usize {
        8
    }
}
