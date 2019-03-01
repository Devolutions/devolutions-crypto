mod dc_hash_v1;
use self::dc_hash_v1::DcHashV1;

use super::DcHeader;
use super::Result;
use super::DevoCryptoError;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom as _;
use std::io::Cursor;


const V1: u16 = 1;

pub enum DcHash {
    V1(DcHashV1),
}

impl DcHash {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcHash> {
        match header.version {
            V1 => Ok(DcHash::V1(DcHashV1::try_from(data)?)),
            _ => panic!()
        }
    }
}


impl Into<Vec<u8>> for DcHash {
    fn into(mut self) -> Vec<u8> {
        match self {
            DcHash::V1(x) => x.into()
        }
    }
}