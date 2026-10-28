//! Module for dealing with signature keys.
//!
//! See the `signature` module for more usage.
//!
//! #### `generate_keypair`
//! Note: A private key is useless on their own as the public key is also required to sign the data.
//! Therefore, you ned to handle use the full keypair as a private key when you want to sign data.
//! ```rust
//! use std::convert::TryInto;
//!
//! use devolutions_crypto::signing_key::{generate_signing_keypair, SigningKeyVersion, SigningKeyPair, SigningPublicKey};
//!
//! let keypair: SigningKeyPair = generate_signing_keypair(SigningKeyVersion::Latest);
//! let public_key: SigningPublicKey = keypair.get_public_key();
//!
//! // You can serialize to and from a byte array to store and transfer the keys
//! let keypair_bytes: Vec<u8> = keypair.into();
//! let public_bytes: Vec<u8> = public_key.into();
//!
//! let keypair: SigningKeyPair = (keypair_bytes.as_slice()).try_into().unwrap();
//! let public_key: SigningPublicKey = (public_bytes.as_slice()).try_into().unwrap();
//! ```

mod signing_key_v1;
#[cfg(feature = "fips")]
mod signing_key_v3;

use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
use super::KeySubtype;
use super::Result;
pub use super::SigningKeyVersion;

use signing_key_v1::{SigningKeyV1Pair, SigningKeyV1Public};
#[cfg(feature = "fips")]
pub(crate) use signing_key_v3::{SigningKeyV3Pair, SigningKeyV3Public};

use std::borrow::Borrow;
use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[cfg(feature = "wbindgen")]
use wasm_bindgen::prelude::*;

/// A public key. This key can be sent in clear on unsecured channels and stored publicly.
#[cfg_attr(feature = "wbindgen", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Debug)]
pub struct SigningPublicKey {
    pub(crate) header: Header<SigningPublicKey>,
    payload: SigningPublicKeyPayload,
}

/// A keypair. This should never be sent over an insecure channel or stored unsecurely.
/// To extract the public part of the keypair, use `get_public_key()`
#[cfg_attr(feature = "wbindgen", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Debug)]
pub struct SigningKeyPair {
    pub(crate) header: Header<SigningKeyPair>,
    payload: SigningKeyPairPayload,
}

impl HeaderType for SigningPublicKey {
    type Version = SigningKeyVersion;
    type Subtype = KeySubtype;

    fn data_type() -> DataType {
        DataType::SigningKey
    }

    fn subtype() -> Self::Subtype {
        KeySubtype::Public
    }
}

impl HeaderType for SigningKeyPair {
    type Version = SigningKeyVersion;
    type Subtype = KeySubtype;

    fn data_type() -> DataType {
        DataType::SigningKey
    }

    fn subtype() -> Self::Subtype {
        KeySubtype::Private
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum SigningKeyPairPayload {
    V1(SigningKeyV1Pair),
    #[cfg(feature = "fips")]
    V3(SigningKeyV3Pair),
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum SigningPublicKeyPayload {
    V1(SigningKeyV1Public),
    #[cfg(feature = "fips")]
    V3(SigningKeyV3Public),
}

/// Generates a `SigningKeyPair` to use in a key exchange or to encrypt data.
///
/// With the `fips` feature, `SigningKeyVersion::Latest` generates an ECDSA P-256 (V3) keypair.
/// `SigningKeyVersion::V1` (Ed25519) can still be generated, but it is not FIPS approved.
/// # Arguments
///  * `version` - Version of the key scheme to use. Use `SigningKeyVersion::Latest` if you're not dealing with shared data.
/// # Returns
/// Returns a `SigningKeyPair` containing the private key and the public key.
/// # Example
/// ```rust
/// use devolutions_crypto::signing_key::{generate_signing_keypair, SigningKeyVersion, SigningKeyPair};
///
/// let keypair: SigningKeyPair = generate_signing_keypair(SigningKeyVersion::Latest);
/// ```
pub fn generate_signing_keypair(version: SigningKeyVersion) -> SigningKeyPair {
    let mut header = Header::default();

    header.version = version.resolve_latest();

    let payload = match header.version {
        SigningKeyVersion::V1 => {
            SigningKeyPairPayload::V1(signing_key_v1::generate_signing_keypair())
        }
        #[cfg(feature = "fips")]
        SigningKeyVersion::V3 => SigningKeyPairPayload::V3(
            signing_key_v3::generate_signing_keypair()
                .expect("the FIPS module key generation should not fail"),
        ),
        SigningKeyVersion::Latest => unreachable!("the version is resolved above"),
    };

    SigningKeyPair { header, payload }
}

impl SigningKeyPair {
    /// The signature scheme matching this keypair.
    pub(crate) fn signature_version(&self) -> crate::SignatureVersion {
        match self.payload {
            SigningKeyPairPayload::V1(_) => crate::SignatureVersion::V1,
            #[cfg(feature = "fips")]
            SigningKeyPairPayload::V3(_) => crate::SignatureVersion::V3,
        }
    }

    /// Gets the public part `SingingPublicKey` of a `SigningKeyPair`
    /// # Returns
    /// Returns a `SingingPublicKey` containingthe public key.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::signing_key::{generate_signing_keypair, SigningKeyVersion, SigningKeyPair, SigningPublicKey};
    ///
    /// let keypair: SigningKeyPair = generate_signing_keypair(SigningKeyVersion::Latest);
    /// let public: SigningPublicKey = keypair.get_public_key();
    /// ```
    pub fn get_public_key(&self) -> SigningPublicKey {
        let mut header = Header::default();

        let payload = match &self.payload {
            SigningKeyPairPayload::V1(x) => {
                header.version = SigningKeyVersion::V1;

                SigningPublicKeyPayload::V1(x.get_public_key())
            }
            #[cfg(feature = "fips")]
            SigningKeyPairPayload::V3(x) => {
                header.version = SigningKeyVersion::V3;

                SigningPublicKeyPayload::V3(x.get_public_key())
            }
        };

        SigningPublicKey { header, payload }
    }
}

impl From<SigningPublicKey> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: SigningPublicKey) -> Self {
        let mut header: Self = data.header.borrow().into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for SigningPublicKey {
    type Error = Error;

    /// Parses the data. Can return an Error of the data is invalid or unrecognized.
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        };

        let header = Header::try_from(&data[0..Header::len()])?;

        if header.data_subtype != KeySubtype::Public {
            return Err(Error::InvalidDataType);
        }

        let payload = match header.version {
            SigningKeyVersion::V1 => {
                SigningPublicKeyPayload::V1(SigningKeyV1Public::try_from(&data[Header::len()..])?)
            }
            #[cfg(feature = "fips")]
            SigningKeyVersion::V3 => {
                SigningPublicKeyPayload::V3(SigningKeyV3Public::try_from(&data[Header::len()..])?)
            }
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<SigningKeyPair> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: SigningKeyPair) -> Self {
        let mut header: Self = data.header.borrow().into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for SigningKeyPair {
    type Error = Error;

    /// Parses the data. Can return an Error of the data is invalid or unrecognized.
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        };

        let header = Header::try_from(&data[0..Header::len()])?;

        if header.data_subtype != KeySubtype::Private {
            return Err(Error::InvalidDataType);
        }

        let payload = match header.version {
            SigningKeyVersion::V1 => {
                SigningKeyPairPayload::V1(SigningKeyV1Pair::try_from(&data[Header::len()..])?)
            }
            #[cfg(feature = "fips")]
            SigningKeyVersion::V3 => {
                SigningKeyPairPayload::V3(SigningKeyV3Pair::try_from(&data[Header::len()..])?)
            }
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<SigningKeyPairPayload> for Vec<u8> {
    fn from(data: SigningKeyPairPayload) -> Self {
        match data {
            SigningKeyPairPayload::V1(x) => x.into(),
            #[cfg(feature = "fips")]
            SigningKeyPairPayload::V3(x) => x.into(),
        }
    }
}

impl From<SigningPublicKeyPayload> for Vec<u8> {
    fn from(data: SigningPublicKeyPayload) -> Self {
        match data {
            SigningPublicKeyPayload::V1(x) => x.into(),
            #[cfg(feature = "fips")]
            SigningPublicKeyPayload::V3(x) => x.into(),
        }
    }
}

impl SigningPublicKey {
    /// Returns the Ed25519 key of a V1 public key.
    pub(crate) fn to_ed25519(&self) -> Result<ed25519_dalek::VerifyingKey> {
        match &self.payload {
            SigningPublicKeyPayload::V1(x) => Ok(ed25519_dalek::VerifyingKey::from(x)),
            #[cfg(feature = "fips")]
            _ => Err(Error::InvalidDataType),
        }
    }

    /// Returns the ECDSA P-256 key of a V3 public key.
    #[cfg(feature = "fips")]
    pub(crate) fn to_p256(&self) -> Result<&SigningKeyV3Public> {
        match &self.payload {
            SigningPublicKeyPayload::V3(x) => Ok(x),
            _ => Err(Error::InvalidDataType),
        }
    }
}

impl SigningKeyPair {
    /// Returns the Ed25519 key of a V1 keypair.
    pub(crate) fn to_ed25519(&self) -> Result<ed25519_dalek::SigningKey> {
        match &self.payload {
            SigningKeyPairPayload::V1(x) => Ok(ed25519_dalek::SigningKey::from(x)),
            #[cfg(feature = "fips")]
            _ => Err(Error::InvalidDataType),
        }
    }

    /// Returns the ECDSA P-256 key of a V3 keypair.
    #[cfg(feature = "fips")]
    pub(crate) fn to_p256(&self) -> Result<&SigningKeyV3Pair> {
        match &self.payload {
            SigningKeyPairPayload::V3(x) => Ok(x),
            _ => Err(Error::InvalidDataType),
        }
    }
}

// With the `fips` feature, a key can be an ECDSA key, so these conversions are not infallible.
#[cfg(not(feature = "fips"))]
impl From<&SigningPublicKey> for ed25519_dalek::VerifyingKey {
    fn from(data: &SigningPublicKey) -> Self {
        data.to_ed25519().expect("only Ed25519 keys exist")
    }
}

#[cfg(not(feature = "fips"))]
impl From<&SigningKeyPair> for ed25519_dalek::SigningKey {
    fn from(data: &SigningKeyPair) -> Self {
        data.to_ed25519().expect("only Ed25519 keys exist")
    }
}

#[test]
fn test_signing_keypair_v1() {
    use std::convert::TryInto;

    let keypair = generate_signing_keypair(SigningKeyVersion::V1);
    let public = keypair.get_public_key();

    let keypair_bytes: Vec<u8> = keypair.into();
    let public_bytes: Vec<u8> = public.into();

    let _: SigningKeyPair = (keypair_bytes.as_slice()).try_into().unwrap();
    let _: SigningPublicKey = (public_bytes.as_slice()).try_into().unwrap();
}
