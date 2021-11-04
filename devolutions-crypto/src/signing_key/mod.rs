//! Module for dealing with wrapped keys and key exchange.
//!
//! For now, this module only deal with keypairs, as the symmetric keys are not wrapped yet.
//!
//! ### Generation/Derivation
//!
//! You have two ways to generate a `KeyPair`: Using `generate_keypair` will generate a random one, using `derive_keypair` will derive one from another password or key along with derivation parameters(including salt). Except in specific circumstances, you should use `generate_keypair`.
//!
//! Asymmetric keys have two uses. They can be used to [encrypt and decrypt data](##asymmetric) and to perform a [key exchange](#key-exchange).
//!
//! #### `generate_keypair`
//! ```rust
//! use devolutions_crypto::key::{generate_keypair, KeyVersion, KeyPair};
//!
//! let keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//! ```
//!
//! #### `derive_keypair`
//! ```rust
//! use devolutions_crypto::Argon2Parameters;
//! use devolutions_crypto::key::{KeyVersion, KeyPair, derive_keypair};
//!
//! let parameters: Argon2Parameters = Default::default();
//! let keypair: KeyPair = derive_keypair(b"thisisapassword", &parameters, KeyVersion::Latest).expect("derivation should not fail");
//! ```
//!
//! ### Key Exchange
//!
//! The goal of using a key exchange is to get a shared secret key between
//! two parties without making it possible for users listening on the conversation
//! to guess that shared key.
//! 1. Alice and Bob generates a `KeyPair` each.
//! 2. Alice and Bob exchanges their `PublicKey`.
//! 3. Alice mix her `PrivateKey` with Bob's `PublicKey`. This gives her the shared key.
//! 4. Bob mixes his `PrivateKey` with Alice's `PublicKey`. This gives him the shared key.
//! 5. Both Bob and Alice has the same shared key, which they can use for symmetric encryption for further communications.
//!
//! ```rust
//! use devolutions_crypto::key::{generate_keypair, mix_key_exchange, KeyVersion, KeyPair};
//!
//! let bob_keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//! let alice_keypair: KeyPair = generate_keypair(KeyVersion::Latest);
//!
//! let bob_shared = mix_key_exchange(&bob_keypair.private_key, &alice_keypair.public_key).expect("key exchange should not fail");
//!
//! let alice_shared = mix_key_exchange(&alice_keypair.private_key, &bob_keypair.public_key).expect("key exchange should not fail");
//!
//! // They now have a shared secret!
//! assert_eq!(bob_shared, alice_shared);
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

// /// An asymmetric keypair.
// #[derive(Clone)]
// pub struct SigningKeyPair {
//     /// The private key of this pair.
//     pub private_key: SigningPrivateKey,
//     /// The public key of this pair.
//     pub public_key: SigningPublicKey,
// }

/// A public key. This key can be sent in clear on unsecured channels and stored publicly.
#[cfg_attr(feature = "wbindgen", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Debug)]
pub struct SigningPublicKey {
    pub(crate) header: Header<SigningPublicKey>,
    payload: SigningPublicKeyPayload,
}

/// A private key. This key should never be sent over an insecure channel or stored unsecurely.
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
