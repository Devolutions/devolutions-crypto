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

mod key_v1;

use super::Argon2Parameters;
use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
use super::KeySubtype;
pub use super::KeyVersion;
use super::Result;

use key_v1::{KeyV1Private, KeyV1Public};

use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// An asymmetric keypair.
#[derive(Clone)]
pub struct KeyPair {
    /// The private key of this pair.
    pub private_key: PrivateKey,
    /// The public key of this pair.
    pub public_key: PublicKey,
}

/// A public key. This key can be sent in clear on unsecured channels and stored publicly.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) header: Header<PublicKey>,
    payload: PublicKeyPayload,
}

/// A private key. This key should never be sent over an insecure channel or stored unsecurely.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Debug)]
pub struct PrivateKey {
    pub(crate) header: Header<PrivateKey>,
    payload: PrivateKeyPayload,
}

impl HeaderType for PublicKey {
    type Version = KeyVersion;
    type Subtype = KeySubtype;

    fn data_type() -> DataType {
        DataType::Key
    }

    fn subtype() -> Self::Subtype {
        KeySubtype::Public
    }
}

impl HeaderType for PrivateKey {
    type Version = KeyVersion;
    type Subtype = KeySubtype;

    fn data_type() -> DataType {
        DataType::Key
    }

    fn subtype() -> Self::Subtype {
        KeySubtype::Private
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum PrivateKeyPayload {
    V1(KeyV1Private),
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum PublicKeyPayload {
    V1(KeyV1Public),
}

/// Generates a `KeyPair` to use in a key exchange or to encrypt data.
/// # Arguments
///  * `version` - Version of the key scheme to use. Use `KeyVersion::Latest` if you're not dealing with shared data.
/// # Returns
/// Returns a `KeyPair` containing the private key and the public key.
/// # Example
/// ```rust
/// use devolutions_crypto::key::{generate_keypair, KeyVersion};
///
/// let keypair = generate_keypair(KeyVersion::Latest);
/// ```
pub fn generate_keypair(version: KeyVersion) -> KeyPair {
    let (private_header, public_header) = keypair_headers(version);

    let (private_key, public_key) = match version {
        KeyVersion::V1 | KeyVersion::Latest => {
            let keypair = key_v1::generate_keypair();
            (
                PrivateKeyPayload::V1(keypair.private_key),
                PublicKeyPayload::V1(keypair.public_key),
            )
        }
    };

    KeyPair {
        private_key: PrivateKey {
            header: private_header,
            payload: private_key,
        },
        public_key: PublicKey {
            header: public_header,
            payload: public_key,
        },
    }
}

/// Derive a `KeyPair` from a password and parameters to use in a key exchange or to encrypt data.
/// # Arguments
///  * `password` - The password to derive.
///  * `parameters` - The derivation  parameters to use. You should use Argon2Parameters::default() for each new
///    key to generate and reuse the same parameters(including the salt) to regenerate the full key.
///  * `version` - Version of the key scheme to use. Use `KeyVersion::Latest` if you're not dealing with shared data.
/// # Returns
/// Returns a `KeyPair` containing the private key and the public key.
/// # Example
/// ```rust
/// use devolutions_crypto::Argon2Parameters;
/// use devolutions_crypto::key::{KeyVersion, KeyPair, derive_keypair};
///
/// let parameters: Argon2Parameters = Default::default();
/// let keypair: KeyPair = derive_keypair(b"thisisapassword", &parameters, KeyVersion::Latest).expect("derivation should not fail");
/// ```
pub fn derive_keypair(
    password: &[u8],
    parameters: &Argon2Parameters,
    version: KeyVersion,
) -> Result<KeyPair> {
    let (private_header, public_header) = keypair_headers(version);

    let (private_key, public_key) = match version {
        KeyVersion::V1 | KeyVersion::Latest => {
            let keypair = key_v1::derive_keypair(password, parameters)?;
            (
                PrivateKeyPayload::V1(keypair.private_key),
                PublicKeyPayload::V1(keypair.public_key),
            )
        }
    };

    Ok(KeyPair {
        private_key: PrivateKey {
            header: private_header,
            payload: private_key,
        },
        public_key: PublicKey {
            header: public_header,
            payload: public_key,
        },
    })
}

/// Mix a `PrivateKey` with another client `PublicKey` to get a secret shared between the two parties.
/// # Arguments
///  * `private_key` - The user's `PrivateKey` obtained through `generate_keypair()`.
///  * `public_key` - The peer's `PublicKey`.
/// # Returns
/// Returns a shared secret in the form of a `Vec<u8>`, which can then be used
///     as an encryption key between the two parties.
/// # Example
/// ```rust
/// use std::convert::TryFrom as _;
/// use devolutions_crypto::key::{PublicKey, PrivateKey, generate_keypair, mix_key_exchange, KeyVersion};
/// # fn send_key_to_alice(_: &[u8]) {}
/// # fn send_key_to_bob(_: &[u8]) {}
/// # fn receive_key_from_alice() {}
/// # fn receive_key_from_bob() {}
///
/// // This happens on Bob's side.
/// let bob_keypair = generate_keypair(KeyVersion::Latest);
/// let bob_serialized_pub: Vec<u8> = bob_keypair.public_key.into();
///
/// send_key_to_alice(&bob_serialized_pub);
///
/// // This happens on Alice's side.
/// let alice_keypair = generate_keypair(KeyVersion::Latest);
/// let alice_serialized_pub: Vec<u8> = alice_keypair.public_key.into();
///
/// send_key_to_bob(&alice_serialized_pub);
///
/// // Bob can now generate the shared secret.
/// let alice_received_serialized_pub = receive_key_from_alice();
/// # let alice_received_serialized_pub = alice_serialized_pub;
/// let alice_received_pub = PublicKey::try_from(alice_received_serialized_pub.as_slice()).unwrap();
///
/// let bob_shared = mix_key_exchange(&bob_keypair.private_key, &alice_received_pub).unwrap();
///
/// // Alice can now generate the shared secret
/// let bob_received_serialized_pub = receive_key_from_bob();
/// # let bob_received_serialized_pub = bob_serialized_pub;
/// let bob_received_pub = PublicKey::try_from(bob_received_serialized_pub.as_slice()).unwrap();
///
/// let alice_shared = mix_key_exchange(&alice_keypair.private_key, &bob_received_pub).unwrap();
///
/// // They now have a shared secret!
/// assert_eq!(bob_shared, alice_shared);
/// ```
pub fn mix_key_exchange(private_key: &PrivateKey, public_key: &PublicKey) -> Result<Vec<u8>> {
    Ok(match (&private_key.payload, &public_key.payload) {
        (PrivateKeyPayload::V1(private_key), PublicKeyPayload::V1(public_key)) => {
            key_v1::mix_key_exchange(&private_key, &public_key)
        } //_ => Err(DevoCryptoError::InvalidDataType),
    })
}

fn keypair_headers(version: KeyVersion) -> (Header<PrivateKey>, Header<PublicKey>) {
    let mut private_header = Header::default();
    let mut public_header = Header::default();

    match version {
        KeyVersion::V1 | KeyVersion::Latest => {
            private_header.version = KeyVersion::V1;
            public_header.version = KeyVersion::V1;
        }
    }

    (private_header, public_header)
}

impl From<PublicKey> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: PublicKey) -> Self {
        let mut header: Self = data.header.into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for PublicKey {
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

        let payload = match KeyVersion::try_from(header.version) {
            Ok(KeyVersion::V1) => {
                PublicKeyPayload::V1(KeyV1Public::try_from(&data[Header::len()..])?)
            }
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<PrivateKey> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: PrivateKey) -> Self {
        let mut header: Self = data.header.into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for PrivateKey {
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

        let payload = match KeyVersion::try_from(header.version) {
            Ok(KeyVersion::V1) => {
                PrivateKeyPayload::V1(KeyV1Private::try_from(&data[Header::len()..])?)
            }
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<PrivateKeyPayload> for Vec<u8> {
    fn from(data: PrivateKeyPayload) -> Self {
        match data {
            PrivateKeyPayload::V1(x) => x.into(),
        }
    }
}

impl From<PublicKeyPayload> for Vec<u8> {
    fn from(data: PublicKeyPayload) -> Self {
        match data {
            PublicKeyPayload::V1(x) => x.into(),
        }
    }
}

impl From<&PublicKey> for x25519_dalek::PublicKey {
    fn from(data: &PublicKey) -> Self {
        match &data.payload {
            PublicKeyPayload::V1(x) => Self::from(x),
            //_ => Err(DevoCryptoError::InvalidDataType),
        }
    }
}

impl From<&PrivateKey> for x25519_dalek::StaticSecret {
    fn from(data: &PrivateKey) -> Self {
        match &data.payload {
            PrivateKeyPayload::V1(x) => Self::from(x),
            //_ => Err(DevoCryptoError::InvalidDataType),
        }
    }
}

#[test]
fn ecdh_test() {
    let bob_keypair = generate_keypair(KeyVersion::Latest);
    let alice_keypair = generate_keypair(KeyVersion::Latest);

    let bob_shared = mix_key_exchange(&bob_keypair.private_key, &alice_keypair.public_key).unwrap();
    let alice_shared =
        mix_key_exchange(&alice_keypair.private_key, &bob_keypair.public_key).unwrap();

    assert_eq!(bob_shared, alice_shared);
}

#[test]
fn derive_keypair_test() {
    let mut bob_parameters = Argon2Parameters::default();
    bob_parameters.memory = 32;
    bob_parameters.iterations = 2;

    let bob_keypair =
        derive_keypair("password1".as_bytes(), &bob_parameters, KeyVersion::Latest).unwrap();
    let bob_keypair2 =
        derive_keypair("password1".as_bytes(), &bob_parameters, KeyVersion::Latest).unwrap();

    // Derivation should be repeatable with the same parameters
    assert_eq!(
        Into::<Vec<u8>>::into(bob_keypair.private_key),
        Into::<Vec<u8>>::into(bob_keypair2.private_key)
    );
    assert_eq!(
        Into::<Vec<u8>>::into(bob_keypair.public_key),
        Into::<Vec<u8>>::into(bob_keypair2.public_key)
    );

    let bob_keypair =
        derive_keypair("password1".as_bytes(), &bob_parameters, KeyVersion::Latest).unwrap();

    let mut alice_parameters = Argon2Parameters::default();
    alice_parameters.memory = 64;
    alice_parameters.iterations = 4;

    let alice_keypair = derive_keypair(
        "password5".as_bytes(),
        &alice_parameters,
        KeyVersion::Latest,
    )
    .unwrap();

    let bob_shared = mix_key_exchange(&bob_keypair.private_key, &alice_keypair.public_key).unwrap();
    let alice_shared =
        mix_key_exchange(&alice_keypair.private_key, &bob_keypair.public_key).unwrap();

    // Should be a regular keypair
    assert_eq!(bob_shared, alice_shared);
}
