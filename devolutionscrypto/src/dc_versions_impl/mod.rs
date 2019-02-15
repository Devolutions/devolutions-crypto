mod dc_hash_impl;

use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

pub use self::dc_hash_impl::hash_from_version;
pub use self::dc_hash_impl::HashImpl;

pub trait DcSerialize {
    fn try_from_header(data: &[u8], header: &DcHeader) -> Result<Self>
    where
        Self: Sized;
    fn into_vec(&mut self) -> Vec<u8>;
}
