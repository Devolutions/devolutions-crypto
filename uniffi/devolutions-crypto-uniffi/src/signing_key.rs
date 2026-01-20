use std::sync::Arc;

use crate::DevolutionsCryptoError;
use crate::Result;
use crate::SigningKeyVersion;

#[derive(uniffi::Object)]
pub struct SigningKeyPair(devolutions_crypto::signing_key::SigningKeyPair);

#[uniffi::export]
impl SigningKeyPair {
    #[uniffi::constructor]
    pub fn new_from_bytes(data: &[u8]) -> Result<Arc<Self>> {
        let inner = data.try_into()?;
        Ok(Arc::new(Self(inner)))
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.0.get_public_key().into()
    }

    pub fn get_private_key(&self) -> Vec<u8> {
        self.0.clone().into()
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

#[uniffi::export(default(version = None))]
pub fn generate_signing_keypair(version: Option<SigningKeyVersion>) -> Arc<SigningKeyPair> {
    let version = version.unwrap_or(SigningKeyVersion::Latest);
    Arc::new(devolutions_crypto::signing_key::generate_signing_keypair(version).into())
}
