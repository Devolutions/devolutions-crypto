mod dc_hash_v1;

use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use self::dc_hash_v1::DcHashV1;

use std::convert::TryFrom as _;

pub const HASH: u16 = 3;

const V1: u16 = 1;

pub enum DcHash {
    V1(DcHashV1),
}

impl DcHash {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcHash> {
        match header.version {
            V1 => Ok(DcHash::V1(DcHashV1::try_from(data)?)),
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }
}

impl From<DcHash> for Vec<u8> {
    fn from(hash: DcHash) -> Vec<u8> {
        match hash {
            DcHash::V1(x) => x.into(),
        }
    }
}

impl DcHash {
    pub fn hash_password(pass: &[u8], iterations: u32, header: &mut DcHeader) -> Result<DcHash> {
        header.data_type = HASH;
        header.version = V1;
        Ok(DcHash::V1(DcHashV1::hash_password(pass, iterations)?))
    }

    pub fn verify_password(&self, pass: &[u8]) -> Result<bool> {
        match self {
            DcHash::V1(x) => x.verify_password(pass),
        }
    }
}
