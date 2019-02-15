pub mod dc_hash_impl_v1;
use super::DcHeader;
use super::DcSerialize;
use super::DevoCryptoError;
use super::Result;

use self::dc_hash_impl_v1::DcHashImplV1;

const V1: u16 = 1;

pub trait HashImpl: DcSerialize {
    fn hash(data: &[u8], iterations: u32) -> Result<Self>
    where
        Self: Sized;
    fn verify(data: &[u8], hash: &[u8]) -> Result<bool>
    where
        Self: Sized;
}

pub fn hash_from_version(data: &[u8], header: &DcHeader) -> Result<Box<HashImpl>> {
    match header.version {
        V1 => Ok(Box::new(DcHashImplV1::try_from_header(data, header)?)),
        _ => panic!(),
    }
}
