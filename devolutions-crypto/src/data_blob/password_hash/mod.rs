mod password_hash_v1;

use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use self::password_hash_v1::DcPasswordHashV1;

use std::convert::TryFrom as _;

pub const PASSWORD_HASH: u16 = 3;

const V1: u16 = 1;

pub enum DcPasswordHash {
    V1(DcPasswordHashV1),
}

impl DcPasswordHash {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcPasswordHash> {
        match header.version {
            V1 => Ok(DcPasswordHash::V1(DcPasswordHashV1::try_from(data)?)),
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }
}

impl From<DcPasswordHash> for Vec<u8> {
    fn from(hash: DcPasswordHash) -> Vec<u8> {
        match hash {
            DcPasswordHash::V1(x) => x.into(),
        }
    }
}

impl DcPasswordHash {
    pub fn hash_password(pass: &[u8], iterations: u32, header: &mut DcHeader) -> Result<DcPasswordHash> {
        header.data_type = PASSWORD_HASH;
        header.version = V1;
        Ok(DcPasswordHash::V1(DcPasswordHashV1::hash_password(pass, iterations)?))
    }

    pub fn verify_password(&self, pass: &[u8]) -> Result<bool> {
        match self {
            DcPasswordHash::V1(x) => x.verify_password(pass),
        }
    }
}
