//! Module for post-quantum key encapsulation (KEM).
//!
//! A sender uses the recipient's `PublicKey` to produce a fresh random `SecretKey` along with an
//! `EncapsulatedKey`. Only the holder of the matching `PrivateKey` can recover the same `SecretKey`
//! from the `EncapsulatedKey`. The resulting `SecretKey` can then be used with the symmetric
//! `ciphertext` functions.
//!
//! This requires a `KeyVersion::V2` keypair. Unlike `mix_key_exchange`,
//! this is a one-way scheme: the sender must transmit the `EncapsulatedKey` to the recipient.
//!
//! ```rust
//! use std::convert::TryFrom as _;
//! use devolutions_crypto::key::{generate_keypair, KeyVersion};
//! use devolutions_crypto::key_encapsulation::{decapsulate, encapsulate, EncapsulatedKey, KeyEncapsulationVersion};
//!
//! // The recipient generates a post-quantum keypair and publishes the public key.
//! let keypair = generate_keypair(KeyVersion::V2);
//!
//! // The sender encapsulates a fresh secret key to the recipient's public key.
//! let (encapsulated, sender_key) = encapsulate(&keypair.public_key, KeyEncapsulationVersion::Latest).expect("encapsulation shouldn't fail");
//! let encapsulated_bytes: Vec<u8> = encapsulated.into();
//!
//! // The recipient recovers the same secret key.
//! let encapsulated = EncapsulatedKey::try_from(encapsulated_bytes.as_slice()).expect("parsing shouldn't fail");
//! let recipient_key = decapsulate(&keypair.private_key, &encapsulated).expect("decapsulation shouldn't fail");
//!
//! assert_eq!(sender_key.as_bytes(), recipient_key.as_bytes());
//! ```

mod key_encapsulation_v1;

use super::DataType;
use super::EncapsulatedKeySubtype;
use super::Error;
use super::Header;
use super::HeaderType;
pub use super::KeyEncapsulationVersion;
use super::Result;

use super::key::{PrivateKey, PublicKey, SecretKey};

use key_encapsulation_v1::EncapsulatedKeyV1;

use std::borrow::Borrow;
use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[cfg(feature = "wbindgen")]
use wasm_bindgen::prelude::*;

/// A versioned encapsulated key. Send it to the holder of the `PrivateKey` so they can recover the `SecretKey`.
#[cfg_attr(feature = "wbindgen", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Debug)]
pub struct EncapsulatedKey {
    pub(crate) header: Header<EncapsulatedKey>,
    payload: EncapsulatedKeyPayload,
}

impl HeaderType for EncapsulatedKey {
    type Version = KeyEncapsulationVersion;
    type Subtype = EncapsulatedKeySubtype;

    fn data_type() -> DataType {
        DataType::EncapsulatedKey
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum EncapsulatedKeyPayload {
    V1(EncapsulatedKeyV1),
}

/// Generates a fresh random `SecretKey` and encapsulates it to a `PublicKey`.
/// # Arguments
///  * `public_key` - The recipient's `PublicKey`. Must be a `KeyVersion::V2` key.
///  * `version` - Version of the key encapsulation scheme to use. Use `KeyEncapsulationVersion::Latest` if you're not dealing with shared data.
/// # Returns
/// Returns the `EncapsulatedKey` to send to the recipient and the `SecretKey` it encapsulates.
/// Returns `Error::InvalidDataType` if the public key is not a `KeyVersion::V2` key,
/// or `Error::RandomError` if the OS random number generator is unavailable.
/// # Example
/// ```rust
/// use devolutions_crypto::key::{generate_keypair, KeyVersion};
/// use devolutions_crypto::key_encapsulation::{encapsulate, KeyEncapsulationVersion};
///
/// let keypair = generate_keypair(KeyVersion::V2);
/// let (encapsulated, secret_key) = encapsulate(&keypair.public_key, KeyEncapsulationVersion::Latest).unwrap();
/// ```
pub fn encapsulate(
    public_key: &PublicKey,
    version: KeyEncapsulationVersion,
) -> Result<(EncapsulatedKey, SecretKey)> {
    let mut header = Header::default();

    let (payload, secret_key) = match version {
        KeyEncapsulationVersion::V1 | KeyEncapsulationVersion::Latest => {
            header.version = KeyEncapsulationVersion::V1;
            let (payload, secret_key) = EncapsulatedKeyV1::encapsulate(public_key)?;
            (EncapsulatedKeyPayload::V1(payload), secret_key)
        }
    };

    Ok((EncapsulatedKey { header, payload }, secret_key))
}

/// Recovers the `SecretKey` encapsulated in an `EncapsulatedKey`.
/// # Arguments
///  * `private_key` - The recipient's `PrivateKey`. Must match the `PublicKey` used by `encapsulate`.
///  * `encapsulated_key` - The `EncapsulatedKey` produced by `encapsulate`.
/// # Returns
/// Returns the encapsulated `SecretKey`.
/// Returns `Error::InvalidDataType` if the private key is not a `KeyVersion::V2` key.
/// Note that, as with any KEM, a wrong private key does not produce an error: it produces a
/// different `SecretKey`, which will fail to authenticate when used for decryption.
/// # Example
/// ```rust
/// use devolutions_crypto::key::{generate_keypair, KeyVersion};
/// use devolutions_crypto::key_encapsulation::{decapsulate, encapsulate, KeyEncapsulationVersion};
///
/// let keypair = generate_keypair(KeyVersion::V2);
/// let (encapsulated, sender_key) = encapsulate(&keypair.public_key, KeyEncapsulationVersion::Latest).unwrap();
/// let recipient_key = decapsulate(&keypair.private_key, &encapsulated).unwrap();
///
/// assert_eq!(sender_key.as_bytes(), recipient_key.as_bytes());
/// ```
pub fn decapsulate(
    private_key: &PrivateKey,
    encapsulated_key: &EncapsulatedKey,
) -> Result<SecretKey> {
    match &encapsulated_key.payload {
        EncapsulatedKeyPayload::V1(x) => x.decapsulate(private_key),
    }
}

impl From<EncapsulatedKey> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: EncapsulatedKey) -> Self {
        let mut header: Self = data.header.borrow().into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for EncapsulatedKey {
    type Error = Error;

    /// Parses the data. Can return an Error if the data is invalid or unrecognized.
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        };

        let header = Header::try_from(&data[0..Header::len()])?;

        let payload = match header.version {
            KeyEncapsulationVersion::V1 => {
                EncapsulatedKeyPayload::V1(EncapsulatedKeyV1::try_from(&data[Header::len()..])?)
            }
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<EncapsulatedKeyPayload> for Vec<u8> {
    fn from(data: EncapsulatedKeyPayload) -> Self {
        match data {
            EncapsulatedKeyPayload::V1(x) => x.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyVersion, generate_keypair};

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let keypair = generate_keypair(KeyVersion::V2);

        let (encapsulated, sender_key) =
            encapsulate(&keypair.public_key, KeyEncapsulationVersion::Latest).unwrap();

        let serialized: Vec<u8> = encapsulated.into();
        assert_eq!(serialized.len(), 1128);

        let encapsulated = EncapsulatedKey::try_from(serialized.as_slice()).unwrap();
        assert_eq!(encapsulated.header.version, KeyEncapsulationVersion::V1);

        let recipient_key = decapsulate(&keypair.private_key, &encapsulated).unwrap();
        assert_eq!(sender_key.as_bytes(), recipient_key.as_bytes());
        assert_eq!(sender_key.as_bytes().len(), 32);
    }

    #[test]
    fn encapsulate_is_randomized() {
        let keypair = generate_keypair(KeyVersion::V2);

        let (encapsulated1, key1) =
            encapsulate(&keypair.public_key, KeyEncapsulationVersion::V1).unwrap();
        let (encapsulated2, key2) =
            encapsulate(&keypair.public_key, KeyEncapsulationVersion::V1).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_ne!(
            Vec::<u8>::from(encapsulated1),
            Vec::<u8>::from(encapsulated2)
        );
    }

    #[test]
    fn decapsulate_wrong_key_yields_different_secret() {
        let keypair = generate_keypair(KeyVersion::V2);
        let other = generate_keypair(KeyVersion::V2);

        let (encapsulated, sender_key) =
            encapsulate(&keypair.public_key, KeyEncapsulationVersion::Latest).unwrap();
        let wrong_key = decapsulate(&other.private_key, &encapsulated).unwrap();

        assert_ne!(sender_key.as_bytes(), wrong_key.as_bytes());
    }

    #[test]
    fn v1_keys_rejected() {
        let keypair = generate_keypair(KeyVersion::V1);
        let v2_keypair = generate_keypair(KeyVersion::V2);

        assert!(matches!(
            encapsulate(&keypair.public_key, KeyEncapsulationVersion::Latest),
            Err(Error::InvalidDataType)
        ));

        let (encapsulated, _) =
            encapsulate(&v2_keypair.public_key, KeyEncapsulationVersion::Latest).unwrap();
        assert!(matches!(
            decapsulate(&keypair.private_key, &encapsulated),
            Err(Error::InvalidDataType)
        ));
    }

    #[test]
    fn invalid_lengths_rejected() {
        let keypair = generate_keypair(KeyVersion::V2);
        let (encapsulated, _) =
            encapsulate(&keypair.public_key, KeyEncapsulationVersion::Latest).unwrap();
        let serialized: Vec<u8> = encapsulated.into();

        for len in [0, Header::len(), serialized.len() - 1] {
            assert!(matches!(
                EncapsulatedKey::try_from(&serialized[..len]),
                Err(Error::InvalidLength)
            ));
        }

        let mut longer = serialized.clone();
        longer.push(0);
        assert!(matches!(
            EncapsulatedKey::try_from(longer.as_slice()),
            Err(Error::InvalidLength)
        ));
    }

    #[test]
    fn other_data_type_rejected() {
        let keypair = generate_keypair(KeyVersion::V2);
        let public_bytes: Vec<u8> = keypair.public_key.into();

        assert!(EncapsulatedKey::try_from(public_bytes.as_slice()).is_err());
    }

    /// The HKDF labels provide domain separation: feeding a V3 ciphertext's KEM bytes to
    /// `decapsulate` must not reveal that ciphertext's AEAD key.
    #[test]
    fn ciphertext_v3_kem_does_not_decapsulate_to_its_aead_key() {
        use crate::ciphertext::{CiphertextVersion, encrypt_asymmetric};
        use crate::key::key_v2::{KEM_CIPHERTEXT_SIZE, KemCiphertext};

        let keypair = generate_keypair(KeyVersion::V2);
        let ciphertext: Vec<u8> =
            encrypt_asymmetric(b"data", &keypair.public_key, CiphertextVersion::V3)
                .unwrap()
                .into();
        let kem_bytes = &ciphertext[Header::len()..Header::len() + KEM_CIPHERTEXT_SIZE];

        // Splice the KEM bytes into an `EncapsulatedKey`.
        let (template, _) = encapsulate(&keypair.public_key, KeyEncapsulationVersion::V1).unwrap();
        let mut encapsulated: Vec<u8> = template.into();
        encapsulated[Header::len()..].copy_from_slice(kem_bytes);
        let encapsulated = EncapsulatedKey::try_from(encapsulated.as_slice()).unwrap();

        let encapsulation_key = decapsulate(&keypair.private_key, &encapsulated).unwrap();

        let kem_ciphertext = KemCiphertext::try_from(kem_bytes).unwrap();
        let aead_key = keypair
            .private_key
            .x_wing_decapsulate(&kem_ciphertext, b"devolutions_crypto ciphertext_v3")
            .unwrap();

        assert_ne!(encapsulation_key.as_bytes(), aead_key.as_slice());
    }
}
