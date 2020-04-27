//! Module for password hashing and verification. Use this if you need to store user passwords.
//!
//! You can use this module to hash a password and validate it afterward. This is the recommended way to verify a user password on login.
//! ```rust
//! use devolutions_crypto::password_hash::{hash_password, PasswordHashVersion};
//!
//! let password = b"somesuperstrongpa$$w0rd!";
//!
//! let hashed_password = hash_password(password, 10000, PasswordHashVersion::Latest);
//!
//! assert!(hashed_password.verify_password(b"somesuperstrongpa$$w0rd!"));
//! assert!(!hashed_password.verify_password(b"someweakpa$$w0rd!"));
//! ```

mod password_hash_v1;

use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
use super::PasswordHashSubtype;
pub use super::PasswordHashVersion;
use super::Result;

use password_hash_v1::PasswordHashV1;

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
}

/// Creates a `PasswordHash` containing the password verifier.
/// # Arguments
///  * `password` - The password to hash.
///  * `iterations` - The number of iterations of the password hash.
///                     A higher number is slower but harder to brute-force.
///                     The recommended is 10000, but the number can be set by the user.
///  * `version` - Version of the library to hash the password with. Use `PasswordHashVersion::Latest` if you're not dealing with shared data.
/// # Returns
/// Returns the `PasswordHash` containing the password verifier.
/// # Example
/// ```rust
/// use devolutions_crypto::password_hash::{hash_password, PasswordHashVersion};
///
/// let password = b"somesuperstrongpa$$w0rd!";
///
/// let hashed_password = hash_password(password, 10000, PasswordHashVersion::Latest);
/// ```
pub fn hash_password(
    password: &[u8],
    iterations: u32,
    version: PasswordHashVersion,
) -> PasswordHash {
    let mut header = Header::default();

    let payload = match version {
        PasswordHashVersion::V1 | PasswordHashVersion::Latest => {
            header.version = PasswordHashVersion::V1;
            PasswordHashPayload::V1(PasswordHashV1::hash_password(password, iterations))
        }
    };

    PasswordHash { header, payload }
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
    /// let hashed_password = hash_password(password, 10000, PasswordHashVersion::Latest);
    /// assert!(hashed_password.verify_password(b"somesuperstrongpa$$w0rd!"));
    /// assert!(!hashed_password.verify_password(b"someweakpa$$w0rd!"));
    /// ```
    pub fn verify_password(&self, password: &[u8]) -> bool {
        match &self.payload {
            PasswordHashPayload::V1(x) => x.verify_password(password),
        }
    }
}

impl From<PasswordHash> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: PasswordHash) -> Self {
        let mut header: Self = data.header.into();
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

        let payload = match PasswordHashVersion::try_from(header.version) {
            Ok(PasswordHashVersion::V1) => {
                PasswordHashPayload::V1(PasswordHashV1::try_from(&data[Header::len()..])?)
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
        }
    }
}

#[test]
fn password_test() {
    let pass = "thisisaveryveryverystrongPa$$w0rd , //".as_bytes();
    let iterations = 10u32;

    let hash = hash_password(pass, iterations, PasswordHashVersion::Latest);

    assert!(hash.verify_password(pass));
    assert!(!hash.verify_password("averybadpassword".as_bytes()))
}
