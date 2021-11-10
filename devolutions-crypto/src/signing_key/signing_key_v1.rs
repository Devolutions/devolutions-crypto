///! Signing Keys V1: ed25519
use super::Error;
use super::Result;

use ed25519_dalek::{Keypair, PublicKey};

use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

pub struct SigningKeyV1Pair {
    keypair: Keypair,
}

impl Clone for SigningKeyV1Pair {
    fn clone(&self) -> Self {
        SigningKeyV1Pair {
            keypair: clone_keypair(&self.keypair),
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
        let keypair: [u8; 64] = Arbitrary::arbitrary(u)?;
        Ok(Self {
            keypair: Keypair::from(private_key),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SigningKeyV1Public {
    key: PublicKey,
}

#[cfg(feature = "fuzz")]
impl Arbitrary for SigningKeyV1Public {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let public_key: [u8; 32] = Arbitrary::arbitrary(u)?;
        Ok(Self {
            key: PublicKey::from(public_key),
        })
    }
}

impl From<SigningKeyV1Pair> for Vec<u8> {
    fn from(key: SigningKeyV1Pair) -> Self {
        key.keypair.to_bytes().to_vec()
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

        match Keypair::from_bytes(key) {
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

        match PublicKey::from_bytes(key) {
            Ok(k) => Ok(Self { key: k }),
            Err(_) => Err(Error::InvalidData),
        }
    }
}

pub fn generate_signing_keypair() -> SigningKeyV1Pair {
    let mut rng = rand_core::OsRng {};
    let keypair = Keypair::generate(&mut rng);

    SigningKeyV1Pair { keypair }
}

impl SigningKeyV1Pair {
    pub fn get_public_key(&self) -> SigningKeyV1Public {
        SigningKeyV1Public {
            key: self.keypair.public,
        }
    }
}

impl From<&SigningKeyV1Public> for PublicKey {
    fn from(data: &SigningKeyV1Public) -> Self {
        data.key
    }
}

impl From<&SigningKeyV1Pair> for Keypair {
    fn from(data: &SigningKeyV1Pair) -> Self {
        clone_keypair(&data.keypair)
    }
}

fn clone_keypair(key: &Keypair) -> Keypair {
    // Unfortunately, the struct does not implement clone, so we need to hack around it
    Keypair::from_bytes(&key.to_bytes())
        .expect("unserializing a freshly serialized key shouldn't fail")
}
