//! Key Derivation V2: Argon2id
use std::convert::TryFrom;

use zeroize::Zeroizing;

use crate::key::{secret_key_from_raw, SecretKey};
use crate::{Argon2Parameters, Error, Header, KeyDerivationVersion, Result};

use super::{DerivationParameters, DerivationParametersPayload};

#[derive(Clone)]
pub struct KeyDerivationV2 {
    pub params: Argon2Parameters,
}

impl core::fmt::Debug for KeyDerivationV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "KeyDerivationV2")
    }
}

impl KeyDerivationV2 {
    pub fn derive(&self, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.params.compute(key)?))
    }
}

impl From<&KeyDerivationV2> for Vec<u8> {
    fn from(v2: &KeyDerivationV2) -> Self {
        Vec::from(&v2.params)
    }
}

impl TryFrom<&[u8]> for KeyDerivationV2 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        Ok(KeyDerivationV2 {
            params: Argon2Parameters::try_from(data)?,
        })
    }
}

// ── Argon2 ───────────────────────────────────────────────────────────────────

/// Derives a key using Argon2id (V2, the default).
pub struct Argon2 {
    params: Argon2Parameters,
}

impl Argon2 {
    /// Creates an `Argon2` key derivation object with default parameters.
    pub fn new() -> Self {
        Self {
            params: Argon2Parameters::default(),
        }
    }

    /// Creates an `Argon2` key derivation object with custom `Argon2Parameters`.
    /// The caller is responsible for managing the salt (use `params.set_salt()` if needed).
    pub fn with_params(params: Argon2Parameters) -> Self {
        Self { params }
    }

    /// Returns a `DerivationParameters` capturing the current Argon2 settings.
    /// Useful for passing custom parameters to [`crate::password_hash::hash_password_with_parameters`].
    pub fn parameters(self) -> DerivationParameters {
        let v2 = KeyDerivationV2 {
            params: self.params,
        };
        let mut header: Header<DerivationParameters> = Header::default();
        header.version = KeyDerivationVersion::V2;
        DerivationParameters {
            header,
            payload: DerivationParametersPayload::V2(v2),
        }
    }

    /// Derives the key using the configured Argon2 parameters.
    /// The salt is embedded in `Argon2Parameters` (generated at construction time when using `new()`).
    pub fn derive(&self, key: &[u8]) -> Result<(SecretKey, DerivationParameters)> {
        let v2 = KeyDerivationV2 {
            params: self.params.clone(),
        };
        let raw = v2.derive(key)?;
        let secret_key = secret_key_from_raw(raw)?;

        let mut header: Header<DerivationParameters> = Header::default();
        header.version = KeyDerivationVersion::V2;

        let derivation_params = DerivationParameters {
            header,
            payload: DerivationParametersPayload::V2(v2),
        };

        Ok((secret_key, derivation_params))
    }
}

impl Default for Argon2 {
    fn default() -> Self {
        Self::new()
    }
}
