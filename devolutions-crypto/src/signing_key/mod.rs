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

use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
use super::KeySubtype;
use super::Result;
pub use super::SigningKeyVersion;

use signing_key_v1::{SigningKeyV1Pair, SigningKeyV1Public};

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
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum SigningPublicKeyPayload {
    V1(SigningKeyV1Public),
}

/// Generates a `SigningKeyPair` to use in a key exchange or to encrypt data.
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

    let payload = match version {
        SigningKeyVersion::V1 | SigningKeyVersion::Latest => {
            header.version = SigningKeyVersion::V1;

            let keypair = signing_key_v1::generate_signing_keypair();
            SigningKeyPairPayload::V1(keypair)
        }
    };

    SigningKeyPair { header, payload }
}

impl SigningKeyPair {
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
        };

        SigningPublicKey { header, payload }
    }
}

impl From<SigningPublicKey> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: SigningPublicKey) -> Self {
        let mut header: Self = data.header.into();
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
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<SigningKeyPair> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: SigningKeyPair) -> Self {
        let mut header: Self = data.header.into();
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
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<SigningKeyPairPayload> for Vec<u8> {
    fn from(data: SigningKeyPairPayload) -> Self {
        match data {
            SigningKeyPairPayload::V1(x) => x.into(),
        }
    }
}

impl From<SigningPublicKeyPayload> for Vec<u8> {
    fn from(data: SigningPublicKeyPayload) -> Self {
        match data {
            SigningPublicKeyPayload::V1(x) => x.into(),
        }
    }
}

impl From<&SigningPublicKey> for ed25519_dalek::PublicKey {
    fn from(data: &SigningPublicKey) -> Self {
        match &data.payload {
            SigningPublicKeyPayload::V1(x) => Self::from(x),
            //_ => Err(DevoCryptoError::InvalidDataType),
        }
    }
}

impl From<&SigningKeyPair> for ed25519_dalek::Keypair {
    fn from(data: &SigningKeyPair) -> Self {
        match &data.payload {
            SigningKeyPairPayload::V1(x) => Self::from(x),
            //_ => Err(DevoCryptoError::InvalidDataType),
        }
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
