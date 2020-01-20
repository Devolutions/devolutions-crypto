use super::DevoCryptoError;
use super::Result;

use std::convert::TryFrom;

use sha2::{ Digest, Sha256 };

use subtle::ConstantTimeEq as _;
use zeroize::Zeroize;

type HashFunction = Sha256;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DcChecksumV1 {
    checksum: Vec<u8>,
}

impl From<DcChecksumV1> for Vec<u8> {
    fn from(checksum: DcChecksumV1) -> Vec<u8> {
        checksum.checksum.clone()
    }
}

impl TryFrom<&[u8]> for DcChecksumV1 {
    type Error = DevoCryptoError;

    fn try_from(data: &[u8]) -> Result<DcChecksumV1> {
        if data.len() != HashFunction::output_size() {
            return Err(DevoCryptoError::InvalidLength);
        };

        let mut checksum = vec![0u8; HashFunction::output_size()];

        checksum.copy_from_slice(data);

        Ok(DcChecksumV1 {
            checksum
        })
    }
}

impl DcChecksumV1 {
    pub fn checksum(data: &[u8]) -> Result<DcChecksumV1> {
        let mut hasher = HashFunction::new();
        hasher.input(data);
        let checksum = hasher.result().to_vec();
        Ok(DcChecksumV1 {
            checksum,
        })
    }

    pub fn validate_checksum(&self, data: &[u8]) -> Result<bool> {
        let mut hasher = HashFunction::new();
        hasher.input(data);
        let checksum = hasher.result().to_vec();
        let is_equal = checksum.ct_eq(&self.checksum).into();
        Ok(is_equal)
    }
}

