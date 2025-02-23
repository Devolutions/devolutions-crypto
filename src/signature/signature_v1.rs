//! Signature V1: ed25519
use super::Error;
use super::Result;

use super::{SigningKeyPair, SigningPublicKey};

use std::convert::TryFrom;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[derive(Clone, Debug)]
pub struct SignatureV1 {
    signature: Signature,
}

#[cfg(feature = "fuzz")]
impl Arbitrary for SignatureV1 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut signature = [0u8; 64];
        u.fill_buffer(&mut signature)?;

        Ok(Self {
            signature: Signature::from_bytes(&signature),
        })
    }
}

impl From<SignatureV1> for Vec<u8> {
    fn from(signature: SignatureV1) -> Vec<u8> {
        signature.signature.to_bytes().to_vec()
    }
}

impl TryFrom<&[u8]> for SignatureV1 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<SignatureV1> {
        if data.len() != 64 {
            return Err(Error::InvalidLength);
        };

        match Signature::try_from(&data[0..64]) {
            Ok(signature) => Ok(SignatureV1 { signature }),
            Err(_) => Err(Error::InvalidData),
        }
    }
}

impl SignatureV1 {
    pub fn sign(data: &[u8], key: &SigningKeyPair) -> Self {
        let key = SigningKey::from(key);
        let signature = key.sign(data);

        Self { signature }
    }

    pub fn verify(&self, data: &[u8], key: &SigningPublicKey) -> bool {
        let key = VerifyingKey::from(key);

        key.verify(data, &self.signature).is_ok()
    }
}
