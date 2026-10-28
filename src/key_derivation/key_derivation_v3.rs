//! Key Derivation V3 (FIPS): PBKDF2-HMAC-SHA256
//!
//! Same layout as V1, computed by the FIPS module. The parameters are checked against the
//! module's approved ranges (SP 800-132) both when they are created and when they are parsed.
use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};
use std::num::NonZeroU32;

use aws_lc_rs::pbkdf2::{self, PBKDF2_HMAC_SHA256};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const KEY_LENGTH: usize = 32;

/// Minimum salt length accepted by the FIPS module (128 bits).
pub const MIN_SALT_LENGTH: usize = 16;
/// Minimum iteration count accepted by the FIPS module.
pub const MIN_ITERATIONS: u32 = 1000;

#[derive(Clone, Debug)]
pub struct KeyDerivationV3 {
    iterations: NonZeroU32,
    salt: Vec<u8>,
}

impl KeyDerivationV3 {
    pub fn new(iterations: u32, salt: Vec<u8>) -> Result<Self> {
        if iterations < MIN_ITERATIONS || salt.len() < MIN_SALT_LENGTH {
            return Err(Error::NotFipsApproved);
        }

        let iterations = NonZeroU32::new(iterations).ok_or(Error::NotFipsApproved)?;
        Ok(Self { iterations, salt })
    }

    pub fn derive(&self, key: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut derived = Zeroizing::new(vec![0u8; KEY_LENGTH]);
        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            self.iterations,
            &self.salt,
            key,
            derived.as_mut_slice(),
        );
        derived
    }
}

impl From<&KeyDerivationV3> for Vec<u8> {
    fn from(params: &KeyDerivationV3) -> Self {
        let mut data = Vec::with_capacity(8 + params.salt.len());
        data.write_u32::<LittleEndian>(params.iterations.get())
            .unwrap();
        data.write_u32::<LittleEndian>(params.salt.len() as u32)
            .unwrap();
        data.write_all(&params.salt).unwrap();
        data
    }
}

impl TryFrom<&[u8]> for KeyDerivationV3 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let iterations = cursor.read_u32::<LittleEndian>()?;
        let salt_len = cursor.read_u32::<LittleEndian>()? as usize;
        let remaining = data.len() - (cursor.position() as usize);

        if remaining != salt_len {
            return Err(Error::InvalidLength);
        }

        let mut salt = vec![0u8; salt_len];
        cursor.read_exact(&mut salt)?;

        KeyDerivationV3::new(iterations, salt).map_err(|_| Error::InvalidData)
    }
}
