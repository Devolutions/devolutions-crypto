use std::sync::Arc;

use crate::SigningKeyVersion;
use crate::Result;
use crate::DevolutionsCryptoError;

pub struct SigningKeyPair(devolutions_crypto::signing_key::SigningKeyPair);

impl SigningKeyPair {
    pub fn new_from_bytes(data: &[u8]) -> Result<Self> {
        data.try_into()
    }
}

impl From<devolutions_crypto::signing_key::SigningKeyPair> for SigningKeyPair {
    fn from(value: devolutions_crypto::signing_key::SigningKeyPair) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for SigningKeyPair {
    type Error = DevolutionsCryptoError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Ok(Self(value.try_into()?))
    }
}

impl SigningKeyPair {
    pub fn get_public_key(&self) -> Vec<u8> {
        self.0.get_public_key().into()
    }

    pub fn get_private_key(&self) -> Vec<u8> {
        self.0.clone().into()
    }
}

pub fn generate_signing_keypair(version: SigningKeyVersion) -> Arc<SigningKeyPair> {
    Arc::new(devolutions_crypto::signing_key::generate_signing_keypair(version).into())
}
