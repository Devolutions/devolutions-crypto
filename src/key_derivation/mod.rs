//! Module for key derivation. Derives a key or password into a `SecretKey`
//! and returns the `DerivationParameters` needed to reproduce the derivation.
//!
//! # Example (Argon2 — default)
//! ```rust
//! use devolutions_crypto::key_derivation::Argon2;
//!
//! let password = b"a very strong password";
//! let argon2 = Argon2::new();
//! let (secret_key, params) = argon2.derive(password).expect("derivation should not fail");
//! // Serialize params to re-derive later:
//! let params_bytes: Vec<u8> = params.into();
//! ```
//!
//! # Example (PBKDF2)
//! ```rust
//! use devolutions_crypto::key_derivation::Pbkdf2;
//!
//! let password = b"a very strong password";
//! let pbkdf2 = Pbkdf2::new();
//! let (secret_key, params) = pbkdf2.derive(password).expect("derivation should not fail");
//! ```

mod key_derivation_v1;
mod key_derivation_v2;

pub use key_derivation_v1::Pbkdf2;
pub use key_derivation_v2::Argon2;

use key_derivation_v1::KeyDerivationV1;
use key_derivation_v2::KeyDerivationV2;

use std::borrow::Borrow;
use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[cfg(feature = "wbindgen")]
use wasm_bindgen::prelude::*;

use zeroize::Zeroizing;

use crate::key::SecretKey;
#[cfg(feature = "fuzz")]
use crate::Argon2Parameters;
use crate::{DataType, Error, Header, HeaderType, KeyDerivationVersion, Result};

use super::enums::KeyDerivationSubtype;

// ── DerivationParameters ─────────────────────────────────────────────────────

/// Serializable parameters that fully describe a completed key derivation.
/// Can be stored alongside a user record to re-derive the same key later.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[cfg_attr(feature = "wbindgen", wasm_bindgen(inspectable))]
pub struct DerivationParameters {
    pub(crate) header: Header<DerivationParameters>,
    pub(super) payload: DerivationParametersPayload,
}

impl HeaderType for DerivationParameters {
    type Version = KeyDerivationVersion;
    type Subtype = KeyDerivationSubtype;

    fn data_type() -> DataType {
        DataType::KeyDerivation
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub(super) enum DerivationParametersPayload {
    V1(KeyDerivationV1),
    V2(KeyDerivationV2),
}

#[cfg(feature = "fuzz")]
impl Arbitrary for KeyDerivationV1 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(KeyDerivationV1 {
            iterations: u32::arbitrary(u)?,
            salt: Vec::<u8>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "fuzz")]
impl Arbitrary for KeyDerivationV2 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(KeyDerivationV2 {
            params: Argon2Parameters::default(),
        })
    }
}

impl From<DerivationParameters> for Vec<u8> {
    fn from(data: DerivationParameters) -> Self {
        let mut header: Self = data.header.borrow().into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for DerivationParameters {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        }

        let header = Header::try_from(&data[0..Header::len()])?;

        let payload = match header.version {
            KeyDerivationVersion::V1 => {
                DerivationParametersPayload::V1(KeyDerivationV1::try_from(&data[Header::len()..])?)
            }
            KeyDerivationVersion::V2 => {
                DerivationParametersPayload::V2(KeyDerivationV2::try_from(&data[Header::len()..])?)
            }
            KeyDerivationVersion::Latest => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<DerivationParametersPayload> for Vec<u8> {
    fn from(payload: DerivationParametersPayload) -> Self {
        match payload {
            DerivationParametersPayload::V1(v1) => Vec::from(&v1),
            DerivationParametersPayload::V2(v2) => Vec::from(&v2),
        }
    }
}

impl DerivationParameters {
    /// Re-derives raw bytes from a password using the stored algorithm and parameters.
    pub fn compute(&self, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match &self.payload {
            DerivationParametersPayload::V1(v1) => Ok(v1.derive(password)),
            DerivationParametersPayload::V2(v2) => v2.derive(password),
        }
    }

    /// Returns the byte-length of the hash that [`compute`](Self::compute) will produce.
    pub fn output_length(&self) -> usize {
        match &self.payload {
            DerivationParametersPayload::V1(_) => key_derivation_v1::KEY_LENGTH,
            DerivationParametersPayload::V2(v2) => v2.params.length as usize,
        }
    }
}

/// Derives a `SecretKey` from `password` using the algorithm selected by `version`.
///
/// * `KeyDerivationVersion::Latest` and `KeyDerivationVersion::V2` use **Argon2id** (recommended).
/// * `KeyDerivationVersion::V1` uses **PBKDF2-HMAC-SHA256**.
///
/// A random salt is generated automatically; the returned [`DerivationParameters`] can be
/// stored alongside the protected data so the same key can be reproduced later.
///
/// # Example
/// ```rust
/// use devolutions_crypto::key_derivation::{derive_key, DerivationParameters};
/// use devolutions_crypto::KeyDerivationVersion;
///
/// let password = b"a very strong password";
/// let (secret_key, params) = derive_key(password, KeyDerivationVersion::Latest).expect("derivation should not fail");
/// // Serialize params to re-derive later:
/// let params_bytes: Vec<u8> = params.into();
/// ```
pub fn derive_key(
    password: &[u8],
    version: KeyDerivationVersion,
) -> Result<(SecretKey, DerivationParameters)> {
    match version {
        KeyDerivationVersion::V1 => Pbkdf2::new().derive(password),
        KeyDerivationVersion::V2 | KeyDerivationVersion::Latest => Argon2::new().derive(password),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::key::secret_key_from_raw;
    use crate::Argon2Parameters;

    use super::*;

    // ── Pbkdf2 ───────────────────────────────────────────────────────────────

    #[test]
    fn pbkdf2_derive_same_input_same_salt_produces_same_key() {
        let pbkdf2 = Pbkdf2::with_params(10);
        let salt = b"fixed_salt_value";
        let (key1, _) = pbkdf2.derive_with_salt(b"password", salt).unwrap();
        let (key2, _) = pbkdf2.derive_with_salt(b"password", salt).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn pbkdf2_derive_different_password_produces_different_key() {
        let pbkdf2 = Pbkdf2::with_params(10);
        let salt = b"fixed_salt_value";
        let (key1, _) = pbkdf2.derive_with_salt(b"password1", salt).unwrap();
        let (key2, _) = pbkdf2.derive_with_salt(b"password2", salt).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn pbkdf2_derive_different_salt_produces_different_key() {
        let pbkdf2 = Pbkdf2::with_params(10);
        let (key1, _) = pbkdf2.derive_with_salt(b"password", b"salt_one").unwrap();
        let (key2, _) = pbkdf2.derive_with_salt(b"password", b"salt_two").unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn pbkdf2_derive_generates_random_salt() {
        let pbkdf2 = Pbkdf2::with_params(10);
        let (_, params1) = pbkdf2.derive(b"password").unwrap();
        let (_, params2) = pbkdf2.derive(b"password").unwrap();
        let bytes1: Vec<u8> = params1.into();
        let bytes2: Vec<u8> = params2.into();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn pbkdf2_derive_with_salt_roundtrip() {
        let pbkdf2 = Pbkdf2::with_params(10);
        let salt = b"roundtrip_salt!!";
        let (key1, params) = pbkdf2.derive_with_salt(b"password", salt).unwrap();

        // Serialize and deserialize params
        let params_bytes: Vec<u8> = params.into();
        let params2 = DerivationParameters::try_from(params_bytes.as_slice()).unwrap();

        // Re-derive using deserialized params
        let payload_bytes: Vec<u8> = params2.payload.into();
        let v1 = KeyDerivationV1::try_from(payload_bytes.as_slice()).unwrap();
        let raw = v1.derive(b"password");
        let key2 = secret_key_from_raw(raw).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn pbkdf2_derivation_parameters_serialize_roundtrip() {
        let pbkdf2 = Pbkdf2::with_params(12345);
        let (_, params) = pbkdf2
            .derive_with_salt(b"password", b"some_salt_here!!")
            .unwrap();
        let bytes: Vec<u8> = params.into();
        let params2 = DerivationParameters::try_from(bytes.as_slice()).unwrap();
        assert_eq!(params2.header.version, KeyDerivationVersion::V1);
    }

    // ── Argon2 ───────────────────────────────────────────────────────────────

    #[test]
    fn argon2_derive_same_params_same_input_produces_same_key() {
        let mut argon2_params = Argon2Parameters::default();
        argon2_params.iterations = 2;
        argon2_params.memory = 64;
        // Fix the salt so derivation is deterministic
        argon2_params.set_salt(b"fixed_salt_16byt".to_vec());

        let argon2 = Argon2::with_params(argon2_params.clone());
        let (key1, _) = argon2.derive(b"password").unwrap();

        let argon2 = Argon2::with_params(argon2_params);
        let (key2, _) = argon2.derive(b"password").unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn argon2_derive_different_salt_produces_different_key() {
        // Two calls to new() generate different salts
        let (key1, _) = Argon2::new().derive(b"password").unwrap();
        let (key2, _) = Argon2::new().derive(b"password").unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn argon2_derivation_parameters_serialize_roundtrip() {
        let mut argon2_params = Argon2Parameters::default();
        argon2_params.iterations = 2;
        argon2_params.memory = 64;
        let (_, params) = Argon2::with_params(argon2_params)
            .derive(b"password")
            .unwrap();
        let bytes: Vec<u8> = params.into();
        let params2 = DerivationParameters::try_from(bytes.as_slice()).unwrap();
        assert_eq!(params2.header.version, KeyDerivationVersion::V2);
    }

    // ── validate_header ───────────────────────────────────────────────────────

    #[test]
    fn validate_header_accepts_key_derivation() {
        use crate::utils::validate_header;
        let (_, params) = Pbkdf2::with_params(10)
            .derive_with_salt(b"pw", b"salt_16bytes!!!")
            .unwrap();
        let bytes: Vec<u8> = params.into();
        assert!(validate_header(&bytes, DataType::KeyDerivation));
    }

    #[test]
    fn validate_header_rejects_wrong_type() {
        use crate::utils::validate_header;
        use crate::DataType;
        let (_, params) = Pbkdf2::with_params(10)
            .derive_with_salt(b"pw", b"salt_16bytes!!!")
            .unwrap();
        let bytes: Vec<u8> = params.into();
        assert!(!validate_header(&bytes, DataType::Ciphertext));
        assert!(!validate_header(&bytes, DataType::Key));
        assert!(!validate_header(&bytes, DataType::PasswordHash));
    }
}
