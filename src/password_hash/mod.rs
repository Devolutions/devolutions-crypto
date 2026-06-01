//! Module for password hashing and verification. Use this if you need to store user passwords.
//!
//! You can use this module to hash a password and validate it afterward. This is the recommended
//! way to verify a user password on login.
//!
//! The default algorithm (`PasswordHashVersion::Latest`) is **Argon2id**.
//!
//! ```rust
//! use devolutions_crypto::password_hash::{hash_password, PasswordHashVersion};
//!
//! let password = b"somesuperstrongpa$$w0rd!";
//!
//! let hashed_password = hash_password(password, PasswordHashVersion::Latest).expect("hash password shouldn't fail");
//!
//! assert!(hashed_password.verify_password(b"somesuperstrongpa$$w0rd!"));
//! assert!(!hashed_password.verify_password(b"someweakpa$$w0rd!"));
//! ```

mod password_hash_v1;
mod password_hash_v2;

use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
use super::PasswordHashSubtype;
pub use super::PasswordHashVersion;
use super::Result;

use super::Argon2;
use super::Argon2Parameters;
use super::DEFAULT_PBKDF2_ITERATIONS;
use crate::key_derivation::DerivationParameters;

use password_hash_v1::PasswordHashV1;
use password_hash_v2::PasswordHashV2;

use std::borrow::Borrow;
use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

/// A versionned password hash. Can be used to validate a password without storing the password.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct PasswordHash {
    pub(crate) header: Header<PasswordHash>,
    payload: PasswordHashPayload,
}

impl HeaderType for PasswordHash {
    type Version = PasswordHashVersion;
    type Subtype = PasswordHashSubtype;

    fn data_type() -> DataType {
        DataType::PasswordHash
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum PasswordHashPayload {
    V1(PasswordHashV1),
    V2(PasswordHashV2),
}

/// Creates a `PasswordHash` containing the password verifier.
///
/// Uses a secure default for each version:
/// - `V1` (PBKDF2-HMAC-SHA256): [`DEFAULT_PBKDF2_ITERATIONS`] iterations.
/// - `V2` / `Latest` (Argon2id): 64 MiB memory, 3 time iterations (OWASP recommendation).
///
/// Use [`hash_password_with_parameters`] when you need to tune the algorithm parameters.
///
/// # Arguments
///  * `password` - The password to hash.
///  * `version` - Version of the algorithm to use. Use `PasswordHashVersion::Latest` if you're
///    not dealing with shared data.
/// # Returns
/// Returns the `PasswordHash` containing the password verifier.
/// # Example
/// ```rust
/// use devolutions_crypto::password_hash::{hash_password, PasswordHashVersion};
///
/// let password = b"somesuperstrongpa$$w0rd!";
///
/// let hashed_password = hash_password(password, PasswordHashVersion::Latest);
/// ```
pub fn hash_password(password: &[u8], version: PasswordHashVersion) -> Result<PasswordHash> {
    let mut header = Header::default();

    let payload = match version {
        PasswordHashVersion::V1 => {
            header.version = PasswordHashVersion::V1;
            PasswordHashPayload::V1(PasswordHashV1::hash_password(
                password,
                DEFAULT_PBKDF2_ITERATIONS,
            )?)
        }
        PasswordHashVersion::V2 | PasswordHashVersion::Latest => {
            header.version = PasswordHashVersion::V2;
            let mut argon2_params = Argon2Parameters::default();
            argon2_params.memory = password_hash_v2::defaults::MEMORY_KIB;
            argon2_params.iterations = password_hash_v2::defaults::ITERATIONS;
            let params = Argon2::with_params(argon2_params).parameters();
            PasswordHashPayload::V2(PasswordHashV2::hash_password(password, params)?)
        }
    };

    Ok(PasswordHash { header, payload })
}

/// Creates a `PasswordHash` using caller-supplied [`DerivationParameters`].
///
/// The derivation algorithm (Argon2id or PBKDF2) is determined by what is encoded inside
/// `params`. Obtain fresh parameters via [`crate::key_derivation::Argon2::parameters`] or
/// [`crate::key_derivation::Pbkdf2::parameters`].
///
/// # Example
/// ```rust
/// use devolutions_crypto::password_hash::hash_password_with_parameters;
/// use devolutions_crypto::key_derivation::Argon2;
/// use devolutions_crypto::Argon2Parameters;
///
/// let mut params_cfg = Argon2Parameters::default();
/// params_cfg.memory = 131072; // 128 MiB
/// params_cfg.iterations = 4;
/// let params = Argon2::with_params(params_cfg).parameters();
///
/// let hash = hash_password_with_parameters(b"pa$$word", params).expect("should not fail");
/// assert!(hash.verify_password(b"pa$$word"));
/// ```
pub fn hash_password_with_parameters(
    password: &[u8],
    params: DerivationParameters,
) -> Result<PasswordHash> {
    let mut header = Header::default();
    header.version = PasswordHashVersion::V2;
    let payload = PasswordHashPayload::V2(PasswordHashV2::hash_password(password, params)?);
    Ok(PasswordHash { header, payload })
}

impl PasswordHash {
    /// Verify if the `PasswordHash` matches with the specified password. Should execute in constant time.
    /// # Arguments
    ///  * `password` - The password to verify.
    /// # Returns
    /// Returns true if the password matches and false if it doesn't.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::password_hash::{hash_password, PasswordHashVersion};
    ///
    /// let password = b"somesuperstrongpa$$w0rd!";
    ///
    /// let hashed_password = hash_password(password, PasswordHashVersion::Latest).expect("hash password shouldn't fail");
    /// assert!(hashed_password.verify_password(b"somesuperstrongpa$$w0rd!"));
    /// assert!(!hashed_password.verify_password(b"someweakpa$$w0rd!"));
    /// ```
    pub fn verify_password(&self, password: &[u8]) -> bool {
        match &self.payload {
            PasswordHashPayload::V1(x) => x.verify_password(password),
            PasswordHashPayload::V2(x) => x.verify_password(password),
        }
    }
}

impl From<PasswordHash> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: PasswordHash) -> Self {
        let mut header: Self = data.header.borrow().into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for PasswordHash {
    type Error = Error;

    /// Parses the data. Can return an Error of the data is invalid or unrecognized.
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        };

        let header = Header::try_from(&data[0..Header::len()])?;

        let payload = match header.version {
            PasswordHashVersion::V1 => {
                PasswordHashPayload::V1(PasswordHashV1::try_from(&data[Header::len()..])?)
            }
            PasswordHashVersion::V2 => {
                PasswordHashPayload::V2(PasswordHashV2::try_from(&data[Header::len()..])?)
            }
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<PasswordHashPayload> for Vec<u8> {
    fn from(data: PasswordHashPayload) -> Self {
        match data {
            PasswordHashPayload::V1(x) => x.into(),
            PasswordHashPayload::V2(x) => x.into(),
        }
    }
}

#[test]
fn hash_password_test() {
    let pass = "thisisaveryveryverystrongPa$$w0rd , //".as_bytes();
    let hash = hash_password(pass, PasswordHashVersion::Latest).unwrap();

    assert!(hash.verify_password(pass));
    assert!(!hash.verify_password("averybadpassword".as_bytes()))
}

#[test]
fn password_v2_roundtrip_bytes() {
    let pass = b"pa$$w0rd";

    let mut argon2_params = Argon2Parameters::default();
    argon2_params.memory = 32;
    argon2_params.iterations = 2;
    let params = Argon2::with_params(argon2_params).parameters();
    let hash = hash_password_with_parameters(pass, params).unwrap();
    let bytes: Vec<u8> = hash.into();

    let hash2 = PasswordHash::try_from(bytes.as_slice()).unwrap();
    assert!(hash2.verify_password(pass));
    assert!(!hash2.verify_password(b"wrongpassword"));
}

#[test]
fn password_v1_roundtrip_bytes() {
    use crate::key_derivation::Pbkdf2;

    let pass = b"pa$$word";
    // Use very low iterations so the test finishes quickly.
    let params = Pbkdf2::with_params(10).parameters().unwrap();
    let hash = hash_password_with_parameters(pass, params).unwrap();
    let bytes: Vec<u8> = hash.into();

    let hash2 = PasswordHash::try_from(bytes.as_slice()).unwrap();
    assert!(hash2.verify_password(pass));
    assert!(!hash2.verify_password(b"wrongpassword"));
}
