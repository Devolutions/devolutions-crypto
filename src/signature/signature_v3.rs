//! Signature V3 (FIPS): ECDSA over NIST P-256 with SHA-256, fixed-length (r || s) encoding
use super::Error;
use super::Result;

use super::{SigningKeyPair, SigningPublicKey};

use std::convert::TryFrom;

use aws_lc_rs::rand::SystemRandom;

const SIGNATURE_LENGTH: usize = 64;

#[derive(Clone, Debug)]
pub struct SignatureV3 {
    signature: [u8; SIGNATURE_LENGTH],
}

impl From<SignatureV3> for Vec<u8> {
    fn from(signature: SignatureV3) -> Vec<u8> {
        signature.signature.to_vec()
    }
}

impl TryFrom<&[u8]> for SignatureV3 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<SignatureV3> {
        if data.len() != SIGNATURE_LENGTH {
            return Err(Error::InvalidLength);
        };

        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature.copy_from_slice(data);
        Ok(SignatureV3 { signature })
    }
}

impl SignatureV3 {
    pub fn sign(data: &[u8], key: &SigningKeyPair) -> Result<Self> {
        let keypair = key.to_p256()?.to_ecdsa_keypair()?;
        let signature = keypair.sign(&SystemRandom::new(), data)?;

        Self::try_from(signature.as_ref())
    }

    pub fn verify(&self, data: &[u8], key: &SigningPublicKey) -> bool {
        let Ok(key) = key.to_p256().and_then(|k| k.to_parsed()) else {
            return false;
        };

        key.verify_sig(data, &self.signature).is_ok()
    }
}
