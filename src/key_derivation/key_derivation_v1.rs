//! Key Derivation V1: PBKDF2-HMAC-SHA256
use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use zeroize::Zeroizing;

use crate::key::SecretKey;
use crate::utils::derive_key_pbkdf2;
use crate::{DEFAULT_PBKDF2_ITERATIONS, Error, Header, KeyDerivationVersion, Result};

use super::{DerivationParameters, DerivationParametersPayload};

pub const KEY_LENGTH: usize = 32;

#[derive(Clone, Debug)]
pub struct KeyDerivationV1 {
    pub iterations: u32,
    pub salt: Vec<u8>,
}

impl KeyDerivationV1 {
    pub fn derive(&self, key: &[u8]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(derive_key_pbkdf2(
            key,
            &self.salt,
            self.iterations,
            KEY_LENGTH,
        ))
    }
}

impl From<&KeyDerivationV1> for Vec<u8> {
    fn from(params: &KeyDerivationV1) -> Self {
        let mut data = Vec::with_capacity(8 + params.salt.len());
        data.write_u32::<LittleEndian>(params.iterations).unwrap();
        data.write_u32::<LittleEndian>(params.salt.len() as u32)
            .unwrap();
        data.write_all(&params.salt).unwrap();
        data
    }
}

impl TryFrom<&[u8]> for KeyDerivationV1 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let iterations = cursor.read_u32::<LittleEndian>()?;
        let salt_len = cursor.read_u32::<LittleEndian>()? as usize;
        let remaining = data.len() - (cursor.position() as usize);

        if remaining < salt_len {
            return Err(Error::InvalidLength);
        }

        let mut salt = vec![0u8; salt_len];
        cursor.read_exact(&mut salt)?;
        Ok(KeyDerivationV1 { iterations, salt })
    }
}

// ── Pbkdf2 ───────────────────────────────────────────────────────────────────

/// Derives a key using PBKDF2-HMAC-SHA256 (V1).
///
/// With the `fips` feature, the derivation is computed by the FIPS module and produces V3
/// parameters. The iteration count must then be at least 1000 and the salt at least 16 bytes,
/// otherwise `Error::NotFipsApproved` is returned.
pub struct Pbkdf2 {
    iterations: u32,
}

impl Pbkdf2 {
    /// Creates a `Pbkdf2` key derivation object with default parameters (600,000 iterations).
    pub fn new() -> Self {
        Self {
            iterations: DEFAULT_PBKDF2_ITERATIONS,
        }
    }

    /// Creates a `Pbkdf2` key derivation object with a custom iteration count.
    /// The output key length is always 32 bytes to match `SecretKey`'s contract.
    pub fn with_params(iterations: u32) -> Self {
        Self { iterations }
    }

    /// Derives the key using a randomly generated salt.
    pub fn derive(&self, key: &[u8]) -> Result<(SecretKey, DerivationParameters)> {
        let mut salt = vec![0u8; 16];
        crate::utils::fill_random(&mut salt)?;
        self.derive_with_salt(key, &salt)
    }

    /// Derives the key using the provided salt.
    pub fn derive_with_salt(
        &self,
        key: &[u8],
        salt: &[u8],
    ) -> Result<(SecretKey, DerivationParameters)> {
        let derivation_params = self.build(salt.to_vec())?;
        let secret_key = derivation_params.derive(key)?;

        Ok((secret_key, derivation_params))
    }

    fn build(&self, salt: Vec<u8>) -> Result<DerivationParameters> {
        let mut header: Header<DerivationParameters> = Header::default();

        #[cfg(not(feature = "fips"))]
        let payload = {
            header.version = KeyDerivationVersion::V1;
            DerivationParametersPayload::V1(KeyDerivationV1 {
                iterations: self.iterations,
                salt,
            })
        };

        #[cfg(feature = "fips")]
        let payload = {
            header.version = KeyDerivationVersion::V3;
            DerivationParametersPayload::V3(super::KeyDerivationV3::new(self.iterations, salt)?)
        };

        Ok(DerivationParameters { header, payload })
    }

    /// Returns a `DerivationParameters` capturing the current PBKDF2 settings with a freshly
    /// generated random salt, without performing any derivation.
    /// Useful for passing custom parameters to [`crate::password_hash::hash_password_with_parameters`].
    pub fn parameters(self) -> Result<DerivationParameters> {
        let mut salt = vec![0u8; 16];
        crate::utils::fill_random(&mut salt)?;
        self.build(salt)
    }
}

impl Default for Pbkdf2 {
    fn default() -> Self {
        Self::new()
    }
}
