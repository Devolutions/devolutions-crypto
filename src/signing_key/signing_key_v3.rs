//! Signing Keys V3 (FIPS): ECDSA over NIST P-256 with SHA-256
use super::Error;
use super::Result;

use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    ParsedPublicKey,
};
use zeroize::Zeroizing;

use std::convert::TryFrom;

const PRIVATE_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 65;

/// The keypair is kept as bytes because `EcdsaKeyPair` is not `Clone`.
/// It is rebuilt (and validated by the module) each time it is used.
#[derive(Clone)]
pub struct SigningKeyV3Pair {
    private_key: Zeroizing<[u8; PRIVATE_KEY_LENGTH]>,
    public_key: SigningKeyV3Public,
}

impl core::fmt::Debug for SigningKeyV3Pair {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> std::result::Result<(), core::fmt::Error> {
        write!(f, "Keypair")
    }
}

#[derive(Clone, Debug)]
pub struct SigningKeyV3Public {
    key: [u8; PUBLIC_KEY_LENGTH],
}

impl From<SigningKeyV3Pair> for Vec<u8> {
    fn from(key: SigningKeyV3Pair) -> Self {
        let mut data = Vec::with_capacity(PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH);
        data.extend_from_slice(key.private_key.as_slice());
        data.extend_from_slice(&key.public_key.key);
        data
    }
}

impl From<SigningKeyV3Public> for Vec<u8> {
    fn from(key: SigningKeyV3Public) -> Self {
        key.key.to_vec()
    }
}

impl TryFrom<&[u8]> for SigningKeyV3Pair {
    type Error = Error;

    fn try_from(key: &[u8]) -> Result<Self> {
        if key.len() != PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH {
            return Err(Error::InvalidLength);
        }

        let (private, public) = key.split_at(PRIVATE_KEY_LENGTH);

        // Make sure both halves are valid and belong together
        EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            private,
            public,
        )?;

        let mut private_key = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
        private_key.copy_from_slice(private);

        Ok(Self {
            private_key,
            public_key: SigningKeyV3Public::try_from(public)?,
        })
    }
}

impl TryFrom<&[u8]> for SigningKeyV3Public {
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
        ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key)?;

        let mut key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        key_bytes.copy_from_slice(key);
        Ok(Self { key: key_bytes })
    }
}

pub fn generate_signing_keypair() -> Result<SigningKeyV3Pair> {
    let keypair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)?;

    let scalar: EcPrivateKeyBin = keypair.private_key().as_be_bytes()?;
    let mut private_key = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
    private_key.copy_from_slice(scalar.as_ref());

    Ok(SigningKeyV3Pair {
        private_key,
        public_key: SigningKeyV3Public::try_from(keypair.public_key().as_ref())?,
    })
}

impl SigningKeyV3Pair {
    pub fn get_public_key(&self) -> SigningKeyV3Public {
        self.public_key.clone()
    }

    pub fn to_ecdsa_keypair(&self) -> Result<EcdsaKeyPair> {
        Ok(EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            self.private_key.as_slice(),
            &self.public_key.key,
        )?)
    }
}

impl SigningKeyV3Public {
    pub fn to_parsed(&self) -> Result<ParsedPublicKey> {
        Ok(ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, self.key)?)
    }
}
