//! Key V3 (FIPS): NIST P-256 ECDH
use super::Error;
use super::Result;

use aws_lc_rs::agreement::{self, ECDH_P256, UnparsedPublicKey};
use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
use zeroize::Zeroizing;

use std::convert::TryFrom;

/// Length of a big-endian P-256 private scalar.
pub const PRIVATE_KEY_LENGTH: usize = 32;
/// Length of an uncompressed SEC1 P-256 public point.
pub const PUBLIC_KEY_LENGTH: usize = 65;

#[derive(Clone)]
pub struct KeyV3Pair {
    pub private_key: KeyV3Private,
    pub public_key: KeyV3Public,
}

/// The private scalar is kept as bytes because `agreement::PrivateKey` is not `Clone`.
/// The key is rebuilt (and validated by the module) each time it is used.
#[derive(Clone)]
pub struct KeyV3Private {
    key: Zeroizing<[u8; PRIVATE_KEY_LENGTH]>,
}

impl core::fmt::Debug for KeyV3Private {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> std::result::Result<(), core::fmt::Error> {
        write!(f, "Private Key")
    }
}

#[derive(Clone, Debug)]
pub struct KeyV3Public {
    key: [u8; PUBLIC_KEY_LENGTH],
}

impl From<KeyV3Private> for Vec<u8> {
    fn from(key: KeyV3Private) -> Self {
        key.key.to_vec()
    }
}

impl From<KeyV3Public> for Vec<u8> {
    fn from(key: KeyV3Public) -> Self {
        key.key.to_vec()
    }
}

impl TryFrom<&[u8]> for KeyV3Private {
    type Error = Error;

    fn try_from(key: &[u8]) -> Result<Self> {
        if key.len() != PRIVATE_KEY_LENGTH {
            return Err(Error::InvalidLength);
        }

        // Make sure the scalar is a valid private key for the curve
        agreement::PrivateKey::from_private_key(&ECDH_P256, key)?;

        let mut key_bytes = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
        key_bytes.copy_from_slice(key);
        Ok(Self { key: key_bytes })
    }
}

impl TryFrom<&[u8]> for KeyV3Public {
    type Error = Error;

    fn try_from(key: &[u8]) -> Result<Self> {
        if key.len() != PUBLIC_KEY_LENGTH {
            return Err(Error::InvalidLength);
        }

        // Only accept the uncompressed SEC1 encoding
        if key[0] != 0x04 {
            return Err(Error::InvalidData);
        }

        // Make sure the point is on the curve
        agreement::ParsedPublicKey::try_from(&UnparsedPublicKey::new(&ECDH_P256, key))?;

        let mut key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        key_bytes.copy_from_slice(key);
        Ok(Self { key: key_bytes })
    }
}

impl KeyV3Private {
    pub fn to_agreement_key(&self) -> Result<agreement::PrivateKey> {
        Ok(agreement::PrivateKey::from_private_key(
            &ECDH_P256,
            self.key.as_slice(),
        )?)
    }

    pub fn compute_public_key(&self) -> Result<KeyV3Public> {
        public_from_agreement_key(&self.to_agreement_key()?)
    }
}

impl KeyV3Public {
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    pub fn to_unparsed(&self) -> UnparsedPublicKey<&[u8]> {
        UnparsedPublicKey::new(&ECDH_P256, self.key.as_slice())
    }
}

pub(crate) fn public_from_agreement_key(private: &agreement::PrivateKey) -> Result<KeyV3Public> {
    let public = private.compute_public_key()?;
    KeyV3Public::try_from(public.as_ref())
}

pub fn generate_keypair() -> Result<KeyV3Pair> {
    let private = agreement::PrivateKey::generate(&ECDH_P256)?;
    let public_key = public_from_agreement_key(&private)?;

    let scalar: EcPrivateKeyBin = private.as_be_bytes()?;
    let mut key = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
    key.copy_from_slice(scalar.as_ref());

    Ok(KeyV3Pair {
        private_key: KeyV3Private { key },
        public_key,
    })
}

pub fn mix_key_exchange(private: &KeyV3Private, public: &KeyV3Public) -> Result<Vec<u8>> {
    let private = private.to_agreement_key()?;

    agreement::agree(
        &private,
        public.to_unparsed(),
        Error::InvalidData,
        |shared| Ok(shared.to_vec()),
    )
}
