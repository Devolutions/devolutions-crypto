//! Signing Keys V1: ed25519
use super::Error;
use super::Result;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

pub struct SigningKeyV1Pair {
    keypair: SigningKey,
}

impl Clone for SigningKeyV1Pair {
    fn clone(&self) -> Self {
        SigningKeyV1Pair {
            keypair: self.keypair.clone(),
        }
    }
}

impl core::fmt::Debug for SigningKeyV1Pair {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> std::result::Result<(), core::fmt::Error> {
        write!(f, "Keypair")
    }
}

#[cfg(feature = "fuzz")]
impl Arbitrary for SigningKeyV1Pair {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut keypair = [0u8; 64];
        u.fill_buffer(&mut keypair)?;

        match SigningKey::from_keypair_bytes(&keypair) {
            Ok(keypair) => Ok(Self { keypair }),
            Err(_) => Err(arbitrary::Error::IncorrectFormat),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SigningKeyV1Public {
    key: VerifyingKey,
}

#[cfg(feature = "fuzz")]
impl Arbitrary for SigningKeyV1Public {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let public_key: [u8; 32] = Arbitrary::arbitrary(u)?;
        match VerifyingKey::from_bytes(&public_key) {
            Ok(key) => Ok(Self { key }),
            Err(_) => Err(arbitrary::Error::IncorrectFormat),
        }
    }
}

impl From<SigningKeyV1Pair> for Vec<u8> {
    fn from(key: SigningKeyV1Pair) -> Self {
        key.keypair.to_keypair_bytes().to_vec()
    }
}

impl From<SigningKeyV1Public> for Vec<u8> {
    fn from(key: SigningKeyV1Public) -> Self {
        key.key.as_bytes().to_vec()
    }
}

impl TryFrom<&[u8]> for SigningKeyV1Pair {
    type Error = Error;

    fn try_from(key: &[u8]) -> Result<Self> {
        if key.len() != 64 {
            return Err(Error::InvalidLength);
        }

        match SigningKey::from_keypair_bytes(key.try_into().unwrap()) {
            Ok(k) => Ok(Self { keypair: k }),
            Err(_) => Err(Error::InvalidData),
        }
    }
}

impl TryFrom<&[u8]> for SigningKeyV1Public {
    type Error = Error;

    fn try_from(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidLength);
        }

        match VerifyingKey::from_bytes(key.try_into().unwrap()) {
            Ok(k) => Ok(Self { key: k }),
            Err(_) => Err(Error::InvalidData),
        }
    }
}

pub fn generate_signing_keypair() -> SigningKeyV1Pair {
    let mut csprng = OsRng;

    let keypair = SigningKey::generate(&mut csprng);

    SigningKeyV1Pair { keypair }
}

impl SigningKeyV1Pair {
    pub fn get_public_key(&self) -> SigningKeyV1Public {
        SigningKeyV1Public {
            key: self.keypair.verifying_key(),
        }
    }
}

impl From<&SigningKeyV1Public> for VerifyingKey {
    fn from(data: &SigningKeyV1Public) -> Self {
        data.key
    }
}

impl From<&SigningKeyV1Pair> for SigningKey {
    fn from(data: &SigningKeyV1Pair) -> Self {
        data.keypair.clone()
    }
}
