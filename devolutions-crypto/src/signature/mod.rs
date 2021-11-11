//! Module for signing and verifying data.
//!
//! ```rust
//! use std::convert::TryInto;
//!
//! use devolutions_crypto::signing_key::{generate_signing_keypair, SigningKeyVersion, SigningKeyPair, SigningPublicKey};
//! use devolutions_crypto::signature::{sign, Signature, SignatureVersion};
//!
//! let keypair: SigningKeyPair = generate_signing_keypair(SigningKeyVersion::Latest);
//! let public_key: SigningPublicKey = keypair.get_public_key();
//!
//! // You can sign data using the keypair.
//! let signature: Signature = sign(b"this is some test data", &keypair, SignatureVersion::Latest);
//!
//! // You can then verify if the signature is valid
//! assert!(signature.verify(b"this is some test data", &public_key));
//! assert!(!signature.verify(b"this is some wrong test data", &public_key));
//!
//! // You can serialize the signature to and from a byte array.
//! let signature_bytes: Vec<u8> = signature.into();
//!
//! let signature: Signature = signature_bytes.as_slice().try_into().expect("This signature should be valid");
//!
//! assert!(signature.verify(b"this is some test data", &public_key));
//! assert!(!signature.verify(b"this is some wrong test data", &public_key));
//! ```
mod signature_v1;

use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
use super::Result;
use super::SignatureSubtype;
pub use super::SignatureVersion;

use super::signing_key::{SigningKeyPair, SigningPublicKey};

use signature_v1::SignatureV1;

use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

/// A versionned signature. Can be used to validate if some data has been tampered.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct Signature {
    pub(crate) header: Header<Signature>,
    payload: SignaturePayload,
}

impl HeaderType for Signature {
    type Version = SignatureVersion;
    type Subtype = SignatureSubtype;

    fn data_type() -> DataType {
        DataType::Signature
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum SignaturePayload {
    V1(SignatureV1),
}

/// Sign some data with a keypair so that anyone knowing the public part of it can verify the signature.
/// # Arguments
///  * `data` - The data you want to sign
///  * `keypair` - The keypair to use to sign the data. Note that the public part of the keypair is also required to sign the data.
///  * `version` - Version of the signature scheme to use. Use `SignatureVersion::Latest` if you're not dealing with shared data.
/// # Returns
/// Returns a `Signature` that can be used to verify if the data has been tempered with or if.
/// # Example
/// ```rust
/// use devolutions_crypto::signing_key::{generate_signing_keypair, SigningKeyVersion, SigningKeyPair};
/// use devolutions_crypto::signature::{sign, Signature, SignatureVersion};
///
/// let keypair: SigningKeyPair = generate_signing_keypair(SigningKeyVersion::Latest);
/// let signature: Signature = sign(b"this is some test data", &keypair, SignatureVersion::Latest);
/// ```
pub fn sign(data: &[u8], keypair: &SigningKeyPair, version: SignatureVersion) -> Signature {
    let mut header = Header::default();

    let payload = match version {
        SignatureVersion::V1 | SignatureVersion::Latest => {
            header.version = SignatureVersion::V1;
            SignaturePayload::V1(SignatureV1::sign(data, keypair))
        }
    };

    Signature { header, payload }
}

impl Signature {
    /// Verify if the signature matches with the specified data and key.
    /// # Arguments
    ///  * `data` - The data that's signed.
    ///  * `public_key` - The public part of the keypair used to sign the data.
    /// # Returns
    /// Returns true if the signature is valid and false if it doesn't.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::signing_key::{generate_signing_keypair, SigningKeyVersion, SigningKeyPair};
    /// use devolutions_crypto::signature::{sign, Signature, SignatureVersion};
    ///
    /// let keypair: SigningKeyPair = generate_signing_keypair(SigningKeyVersion::Latest);
    /// let signature: Signature = sign(b"this is some test data", &keypair, SignatureVersion::Latest);
    ///
    /// assert!(signature.verify(b"this is some test data", &keypair.get_public_key()));
    /// ```
    pub fn verify(&self, data: &[u8], public_key: &SigningPublicKey) -> bool {
        match &self.payload {
            SignaturePayload::V1(x) => x.verify(data, public_key),
        }
    }
}

impl From<Signature> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: Signature) -> Self {
        let mut header: Self = data.header.into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    /// Parses the data. Can return an Error of the data is invalid or unrecognized.
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        };

        let header = Header::try_from(&data[0..Header::len()])?;

        let payload = match header.version {
            SignatureVersion::V1 => {
                SignaturePayload::V1(SignatureV1::try_from(&data[Header::len()..])?)
            }
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<SignaturePayload> for Vec<u8> {
    fn from(data: SignaturePayload) -> Self {
        match data {
            SignaturePayload::V1(x) => x.into(),
        }
    }
}

#[test]
fn test_signature_v1() {
    use std::convert::TryInto;

    let data = b"this is a test";
    let wrong_data = b"this is wrong";

    let keypair = crate::signing_key::generate_signing_keypair(crate::SigningKeyVersion::V1);
    let public = keypair.get_public_key();

    let keypair2 = crate::signing_key::generate_signing_keypair(crate::SigningKeyVersion::V1);
    let public2 = keypair2.get_public_key();

    let sig1 = sign(data, &keypair, SignatureVersion::V1);

    assert!(sig1.verify(data, &public));
    assert!(!sig1.verify(data, &public2));
    assert!(!sig1.verify(wrong_data, &public));
    assert!(!sig1.verify(wrong_data, &public2));

    let keypair_bytes: Vec<u8> = keypair.into();
    let public_bytes: Vec<u8> = public.into();

    let keypair_parsed: SigningKeyPair = (keypair_bytes.as_slice()).try_into().unwrap();
    let public_parsed: SigningPublicKey = (public_bytes.as_slice()).try_into().unwrap();

    let sig2 = sign(data, &keypair_parsed, SignatureVersion::V1);
    assert!(sig1.verify(data, &public_parsed));
    assert!(sig2.verify(data, &public_parsed));
}
