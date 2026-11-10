//! Module for dealing with wrapped keys and key exchange.
//!
//! ### Generation/Derivation
//!
//! Using `generate_keypair` will generate a random keypair.
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
pub(crate) mod key_v2;
mod secret_key_v1;

use super::DataType;
use super::Error;
use super::Header;
use super::HeaderType;
use super::KeySubtype;
pub use super::KeyVersion;
use super::Result;

use key_v1::{KeyV1Private, KeyV1Public};
use key_v2::{KemCiphertext, KeyV2Private, KeyV2Public};
use secret_key_v1::SecretKeyV1;

use std::borrow::Borrow;
use std::convert::TryFrom;

use zeroize::Zeroizing;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[cfg(feature = "wbindgen")]
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
#[cfg_attr(feature = "wbindgen", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) header: Header<PublicKey>,
    payload: PublicKeyPayload,
}

/// A private key. This key should never be sent over an insecure channel or stored unsecurely.
#[cfg_attr(feature = "wbindgen", wasm_bindgen(inspectable))]
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
    V2(KeyV2Private),
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum PublicKeyPayload {
    V1(KeyV1Public),
    V2(KeyV2Public),
}

/// Generates a `KeyPair` to use in a key exchange or to encrypt data.
/// # Arguments
///  * `version` - Version of the key scheme to use. Use `KeyVersion::Latest` if you're not dealing with shared data.
///    `KeyVersion::V2` generates a X-Wing keypair, usable with
///    `CiphertextVersion::V3` and the `key_encapsulation` module but not with `mix_key_exchange`.
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
        KeyVersion::V2 => {
            let keypair = key_v2::generate_keypair();
            (
                PrivateKeyPayload::V2(keypair.private_key),
                PublicKeyPayload::V2(keypair.public_key),
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

/// Mix a `PrivateKey` with another client `PublicKey` to get a secret shared between the two parties.
/// # Arguments
///  * `private_key` - The user's `PrivateKey` obtained through `generate_keypair()`.
///  * `public_key` - The peer's `PublicKey`.
/// # Returns
/// Returns a shared secret in the form of a `Vec<u8>`, which can then be used
///     as an encryption key between the two parties.
/// Returns `Error::InvalidDataType` if either key is not a `KeyVersion::V1` key: X-Wing (`KeyVersion::V2`)
///     keys are a KEM and cannot perform a non-interactive key exchange. Use the `key_encapsulation` module instead.
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
    match (&private_key.payload, &public_key.payload) {
        (PrivateKeyPayload::V1(private_key), PublicKeyPayload::V1(public_key)) => {
            key_v1::mix_key_exchange(private_key, public_key)
        }
        _ => Err(Error::InvalidDataType),
    }
}

fn keypair_headers(version: KeyVersion) -> (Header<PrivateKey>, Header<PublicKey>) {
    let mut private_header = Header::default();
    let mut public_header = Header::default();

    match version {
        KeyVersion::V1 | KeyVersion::Latest => {
            private_header.version = KeyVersion::V1;
            public_header.version = KeyVersion::V1;
        }
        KeyVersion::V2 => {
            private_header.version = KeyVersion::V2;
            public_header.version = KeyVersion::V2;
        }
    }

    (private_header, public_header)
}

impl From<PublicKey> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: PublicKey) -> Self {
        let mut header: Self = data.header.borrow().into();
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

        let payload = match header.version {
            KeyVersion::V1 => PublicKeyPayload::V1(KeyV1Public::try_from(&data[Header::len()..])?),
            KeyVersion::V2 => PublicKeyPayload::V2(KeyV2Public::try_from(&data[Header::len()..])?),
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<PrivateKey> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: PrivateKey) -> Self {
        let mut header: Self = data.header.borrow().into();
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

        let payload = match header.version {
            KeyVersion::V1 => {
                PrivateKeyPayload::V1(KeyV1Private::try_from(&data[Header::len()..])?)
            }
            KeyVersion::V2 => {
                PrivateKeyPayload::V2(KeyV2Private::try_from(&data[Header::len()..])?)
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
            PrivateKeyPayload::V2(x) => x.into(),
        }
    }
}

impl From<PublicKeyPayload> for Vec<u8> {
    fn from(data: PublicKeyPayload) -> Self {
        match data {
            PublicKeyPayload::V1(x) => x.into(),
            PublicKeyPayload::V2(x) => x.into(),
        }
    }
}

impl PublicKey {
    /// Returns the X25519 key of a `KeyVersion::V1` key, or `Error::InvalidDataType` for other versions.
    pub(crate) fn as_x25519(&self) -> Result<x25519_dalek::PublicKey> {
        match &self.payload {
            PublicKeyPayload::V1(x) => Ok(x25519_dalek::PublicKey::from(x)),
            _ => Err(Error::InvalidDataType),
        }
    }

    /// Encapsulates to a `KeyVersion::V2` (X-Wing) key and returns the KEM ciphertext along with
    /// HKDF-SHA-256(shared secret, `info`). Returns `Error::InvalidDataType` for other versions.
    pub(crate) fn x_wing_encapsulate(
        &self,
        info: &[u8],
    ) -> Result<(Box<KemCiphertext>, Zeroizing<[u8; 32]>)> {
        match &self.payload {
            PublicKeyPayload::V2(x) => Ok(x.encapsulate(info)),
            _ => Err(Error::InvalidDataType),
        }
    }
}

impl PrivateKey {
    /// Returns the X25519 secret of a `KeyVersion::V1` key, or `Error::InvalidDataType` for other versions.
    pub(crate) fn as_x25519(&self) -> Result<x25519_dalek::StaticSecret> {
        match &self.payload {
            PrivateKeyPayload::V1(x) => Ok(x25519_dalek::StaticSecret::from(x)),
            _ => Err(Error::InvalidDataType),
        }
    }

    /// Decapsulates with a `KeyVersion::V2` (X-Wing) key and returns HKDF-SHA-256(shared secret, `info`).
    /// Returns `Error::InvalidDataType` for other versions.
    pub(crate) fn x_wing_decapsulate(
        &self,
        ciphertext: &KemCiphertext,
        info: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        match &self.payload {
            PrivateKeyPayload::V2(x) => x.decapsulate(ciphertext, info),
            _ => Err(Error::InvalidDataType),
        }
    }
}

/// A secret key for symmetric encryption. Should never be sent over an insecure channel or stored unsecurely.
#[cfg_attr(feature = "wbindgen", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Debug)]
pub struct SecretKey {
    pub(crate) header: Header<SecretKey>,
    payload: SecretKeyPayload,
}

impl HeaderType for SecretKey {
    type Version = KeyVersion;
    type Subtype = KeySubtype;

    fn data_type() -> DataType {
        DataType::Key
    }

    fn subtype() -> Self::Subtype {
        KeySubtype::Secret
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum SecretKeyPayload {
    V1(SecretKeyV1),
}

impl SecretKey {
    /// Returns the raw key bytes for use with symmetric encryption primitives.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.payload {
            SecretKeyPayload::V1(k) => k.as_bytes(),
        }
    }
}

/// Constructs a `SecretKey` from raw derived key bytes (must be exactly 32 bytes).
/// Takes ownership of the `Zeroizing` wrapper to ensure the raw bytes are cleared on drop.
pub(crate) fn secret_key_from_raw(bytes: Zeroizing<Vec<u8>>) -> Result<SecretKey> {
    let mut header: Header<SecretKey> = Header::default();
    header.version = KeyVersion::V1;
    let payload = SecretKeyPayload::V1(SecretKeyV1::try_from(bytes.as_slice())?);
    Ok(SecretKey { header, payload })
}

/// Generates a `SecretKey` for use with symmetric encryption.
/// # Arguments
///  * `version` - Version of the key scheme to use. Use `KeyVersion::Latest` if you're not dealing with shared data.
///    Secret keys only exist in version 1; `KeyVersion::V2` only applies to asymmetric keys and also yields a V1 secret key.
/// # Returns
/// Returns a `SecretKey` containing the raw key material.
/// # Example
/// ```rust
/// use devolutions_crypto::key::{generate_secret_key, KeyVersion};
///
/// let key = generate_secret_key(KeyVersion::Latest);
/// ```
pub fn generate_secret_key(version: KeyVersion) -> SecretKey {
    let mut header: Header<SecretKey> = Header::default();

    match version {
        KeyVersion::V1 | KeyVersion::V2 | KeyVersion::Latest => {
            header.version = KeyVersion::V1;
        }
    }

    SecretKey {
        header,
        payload: SecretKeyPayload::V1(SecretKeyV1::generate()),
    }
}

impl From<SecretKey> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: SecretKey) -> Self {
        let mut header: Self = data.header.borrow().into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    /// Parses the data. Can return an Error if the data is invalid or unrecognized.
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        };

        let header = Header::try_from(&data[0..Header::len()])?;

        if header.data_subtype != KeySubtype::Secret {
            return Err(Error::InvalidDataType);
        }

        let payload = match header.version {
            KeyVersion::V1 => SecretKeyPayload::V1(SecretKeyV1::try_from(&data[Header::len()..])?),
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<SecretKeyPayload> for Vec<u8> {
    fn from(data: SecretKeyPayload) -> Self {
        match data {
            SecretKeyPayload::V1(x) => x.into(),
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
fn secret_key_generate_roundtrip() {
    let key = generate_secret_key(KeyVersion::Latest);
    let original_bytes = key.as_bytes().to_vec();

    let serialized: Vec<u8> = key.into();
    let deserialized = SecretKey::try_from(serialized.as_slice()).unwrap();

    assert_eq!(deserialized.as_bytes(), original_bytes.as_slice());
}

#[test]
fn secret_key_wrong_subtype_rejected() {
    use std::convert::TryFrom as _;
    let keypair = generate_keypair(KeyVersion::Latest);
    let private_bytes: Vec<u8> = keypair.private_key.into();

    let result = SecretKey::try_from(private_bytes.as_slice());
    assert!(matches!(result, Err(Error::InvalidDataType)));
}

#[test]
fn secret_key_wrong_length_rejected() {
    let short = [0u8; 4];
    let result = SecretKey::try_from(short.as_slice());
    assert!(matches!(result, Err(Error::InvalidLength)));
}

#[test]
fn keypair_v2_roundtrip() {
    let keypair = generate_keypair(KeyVersion::V2);
    assert_eq!(keypair.private_key.header.version, KeyVersion::V2);
    assert_eq!(keypair.public_key.header.version, KeyVersion::V2);

    let private_bytes: Vec<u8> = keypair.private_key.into();
    let public_bytes: Vec<u8> = keypair.public_key.into();
    assert_eq!(private_bytes.len(), 8 + 32);
    assert_eq!(public_bytes.len(), 8 + 1216);

    let private_key = PrivateKey::try_from(private_bytes.as_slice()).unwrap();
    let public_key = PublicKey::try_from(public_bytes.as_slice()).unwrap();
    assert_eq!(private_key.header.version, KeyVersion::V2);
    assert_eq!(public_key.header.version, KeyVersion::V2);

    assert_eq!(Vec::<u8>::from(private_key), private_bytes);
    assert_eq!(Vec::<u8>::from(public_key), public_bytes);
}

#[test]
fn keypair_v2_private_key_debug_is_redacted() {
    let keypair = generate_keypair(KeyVersion::V2);
    let debug = format!("{:?}", keypair.private_key);
    assert!(debug.contains("Private Key"));
}

#[test]
fn keypair_v2_invalid_lengths_rejected() {
    let keypair = generate_keypair(KeyVersion::V2);
    let private_bytes: Vec<u8> = keypair.private_key.into();
    let public_bytes: Vec<u8> = keypair.public_key.into();

    assert!(matches!(
        PrivateKey::try_from(&private_bytes[..private_bytes.len() - 1]),
        Err(Error::InvalidLength)
    ));
    assert!(matches!(
        PublicKey::try_from(&public_bytes[..public_bytes.len() - 1]),
        Err(Error::InvalidLength)
    ));

    let mut longer = public_bytes.clone();
    longer.push(0);
    assert!(matches!(
        PublicKey::try_from(longer.as_slice()),
        Err(Error::InvalidLength)
    ));
}

#[test]
fn keypair_v2_invalid_ml_kem_public_key_rejected() {
    let keypair = generate_keypair(KeyVersion::V2);
    let mut public_bytes: Vec<u8> = keypair.public_key.into();

    // The first 12-bit ML-KEM coefficient becomes 0xFFF, which is not reduced modulo q = 3329.
    public_bytes[8] = 0xFF;
    public_bytes[9] |= 0x0F;

    assert!(matches!(
        PublicKey::try_from(public_bytes.as_slice()),
        Err(Error::InvalidData)
    ));
}

#[test]
fn mix_key_exchange_rejects_v2_keys() {
    let v1 = generate_keypair(KeyVersion::V1);
    let v2 = generate_keypair(KeyVersion::V2);

    assert!(matches!(
        mix_key_exchange(&v2.private_key, &v2.public_key),
        Err(Error::InvalidDataType)
    ));
    assert!(matches!(
        mix_key_exchange(&v1.private_key, &v2.public_key),
        Err(Error::InvalidDataType)
    ));
    assert!(matches!(
        mix_key_exchange(&v2.private_key, &v1.public_key),
        Err(Error::InvalidDataType)
    ));
}

#[test]
fn latest_keypair_is_still_v1() {
    let keypair = generate_keypair(KeyVersion::Latest);
    assert_eq!(keypair.private_key.header.version, KeyVersion::V1);
    assert_eq!(keypair.public_key.header.version, KeyVersion::V1);
}
