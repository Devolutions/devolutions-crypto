//! Password Hash V2: Argon2id via [`crate::key_derivation::DerivationParameters`].
//!
//! The on-disk payload layout (after the 8-byte [`crate::Header`]) is:
//!
//! ```text
//! [ u32 LE: params_len ][ DerivationParameters bytes (params_len) ][ hash bytes ]
//! ```
use std::convert::TryFrom;
use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::key_derivation::DerivationParameters;
use crate::{Error, Result};

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

pub mod defaults {
    /// Memory cost in KiB (64 MiB).
    pub const MEMORY_KIB: u32 = 65536;
    /// Time cost (number of passes).
    pub const ITERATIONS: u32 = 3;
}

/// Argon2id-backed password verifier (V2).
///
/// Stores the [`DerivationParameters`] (algorithm + salt) together with the derived hash so
/// that verification can reproduce the derivation deterministically.
#[derive(Clone, Debug)]
pub struct PasswordHashV2 {
    pub(super) params: DerivationParameters,
    hash: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "fuzz")]
impl Arbitrary for PasswordHashV2 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            params: DerivationParameters::arbitrary(u)?,
            hash: Zeroizing::new(Vec::<u8>::arbitrary(u)?),
        })
    }
}

impl PasswordHashV2 {
    /// Hashes `pass` using the supplied `params` and returns the verifier.
    pub fn hash_password(pass: &[u8], params: DerivationParameters) -> Result<PasswordHashV2> {
        let hash = params.compute(pass)?;
        Ok(PasswordHashV2 { params, hash })
    }

    /// Returns `true` if `pass` reproduces the stored hash.
    pub fn verify_password(&self, pass: &[u8]) -> bool {
        match self.params.compute(pass) {
            Ok(derived) => derived.ct_eq(&self.hash).into(),
            Err(_) => false,
        }
    }
}

impl From<PasswordHashV2> for Vec<u8> {
    fn from(v2: PasswordHashV2) -> Vec<u8> {
        let params_bytes: Vec<u8> = v2.params.into();
        let params_len = params_bytes.len() as u32;
        let mut data = Vec::with_capacity(4 + params_bytes.len() + v2.hash.len());
        data.write_u32::<LittleEndian>(params_len).unwrap();
        data.extend_from_slice(&params_bytes);
        data.extend_from_slice(&v2.hash);
        data
    }
}

impl TryFrom<&[u8]> for PasswordHashV2 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidLength);
        }
        let mut cursor = Cursor::new(data);
        let params_len = cursor.read_u32::<LittleEndian>()? as usize;
        let pos = cursor.position() as usize;

        let params_end = pos.checked_add(params_len).ok_or(Error::InvalidLength)?;
        if data.len() < params_end {
            return Err(Error::InvalidLength);
        }
        let params = DerivationParameters::try_from(&data[pos..params_end])?;

        let hash_bytes = &data[params_end..];
        if hash_bytes.len() != params.output_length() {
            return Err(Error::InvalidLength);
        }

        Ok(PasswordHashV2 {
            params,
            hash: Zeroizing::new(hash_bytes.to_vec()),
        })
    }
}
