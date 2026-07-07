//! SecretKey V1: 32 raw random bytes
use super::Error;
use super::Result;

use zeroize::Zeroizing;

use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[derive(Clone)]
pub struct SecretKeyV1 {
    key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for SecretKeyV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> std::result::Result<(), core::fmt::Error> {
        write!(f, "Secret Key")
    }
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for SecretKeyV1 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let key: [u8; 32] = Arbitrary::arbitrary(u)?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }
}

impl SecretKeyV1 {
    pub fn generate() -> Self {
        let key =
            crate::utils::random_bytes::<32>().expect("the OS entropy source should be available");
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl From<SecretKeyV1> for Vec<u8> {
    fn from(key: SecretKeyV1) -> Self {
        key.key.as_ref().to_vec()
    }
}

impl TryFrom<&[u8]> for SecretKeyV1 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() != 32 {
            return Err(Error::InvalidLength);
        }

        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(data);
        Ok(Self { key })
    }
}
