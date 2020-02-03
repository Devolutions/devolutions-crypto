mod checksum_v1;

use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use self::checksum_v1::DcChecksumV1;

use std::convert::TryFrom as _;

pub const CHECKSUM: u16 = 4;

const V1: u16 = 1;

pub enum DcChecksum {
    V1(DcChecksumV1),
}

impl DcChecksum {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcChecksum> {
        match header.version {
            V1 => Ok(DcChecksum::V1(DcChecksumV1::try_from(data)?)),
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }
}

impl From<DcChecksum> for Vec<u8> {
    fn from(hash: DcChecksum) -> Vec<u8> {
        match hash {
            DcChecksum::V1(x) => x.into(),
        }
    }
}

impl DcChecksum {
    pub fn checksum(
        data: &[u8],
        header: &mut DcHeader,
        version: Option<u16>,
    ) -> Result<DcChecksum> {
        header.data_type = CHECKSUM;

        match version {
            Some(V1) | None => {
                header.version = V1;
                Ok(DcChecksum::V1(DcChecksumV1::checksum(data)?))
            }
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }

    pub fn validate_checksum(&self, data: &[u8]) -> Result<bool> {
        match self {
            DcChecksum::V1(x) => x.validate_checksum(data),
        }
    }
}
