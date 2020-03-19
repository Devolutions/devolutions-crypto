mod key_v1;

use super::Argon2Parameters;
use super::DataType;
use super::Error;
use super::Header;
use super::KeySubtype;
pub use super::KeyVersion;
use super::Result;

use key_v1::{KeyV1Private, KeyV1Public};

use std::convert::TryFrom;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[derive(Clone)]
pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) header: Header<KeySubtype, KeyVersion>,
    payload: PublicKeyPayload,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[derive(Clone)]
pub struct PrivateKey {
    pub(crate) header: Header<KeySubtype, KeyVersion>,
    payload: PrivateKeyPayload,
}

#[derive(Clone)]
enum PrivateKeyPayload {
    V1(KeyV1Private),
}

#[derive(Clone)]
enum PublicKeyPayload {
    V1(KeyV1Public),
}

/// Generates a key pair to use in a key exchange or to encrypt data.
/// # Returns
/// Returns a KeyPair containing the private key and the public key.
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

/// Generate a keypair from a password and parameters.
/// # Arguments
///  * `password` - The password to derive.
///  * `parameters` - The derivation  parameters to use. You should use Argon2Parameters::default() for each new
///    key to generate and reuse the same parameters(including the salt) to regenerate the full key.
/// # Returns
/// A tuple containing a Private key and a Public key, in that order.
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

/// Mix a private key with another client public key to get a shared secret.
/// # Arguments
///  * `self` - The user's private key obtained through `generate_keypair`.
///  * `public` - The peer public key.
/// # Returns
/// Returns a shared secret in the form of a `Vec<u8>`, which can then be used
///     as an encryption key between the two peers.
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

fn keypair_headers(
    version: KeyVersion,
) -> (
    Header<KeySubtype, KeyVersion>,
    Header<KeySubtype, KeyVersion>,
) {
    let mut private_header = Header::default();
    let mut public_header = Header::default();

    private_header.data_type = DataType::Key;
    public_header.data_type = DataType::Key;

    private_header.data_subtype = KeySubtype::Private;
    public_header.data_subtype = KeySubtype::Public;

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

        if header.data_type != DataType::Key || header.data_subtype != KeySubtype::Public {
            return Err(Error::InvalidDataType);
        }

        let payload = match KeyVersion::try_from(header.version) {
            Ok(KeyVersion::V1) => PublicKeyPayload::V1(KeyV1Public::from(&data[Header::len()..])),
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

        if header.data_type != DataType::Key || header.data_subtype != KeySubtype::Private {
            return Err(Error::InvalidDataType);
        }

        let payload = match KeyVersion::try_from(header.version) {
            Ok(KeyVersion::V1) => PrivateKeyPayload::V1(KeyV1Private::from(&data[Header::len()..])),
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
