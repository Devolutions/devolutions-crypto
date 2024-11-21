use crate::KeyVersion;
use crate::Result;

pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl From<devolutions_crypto::key::KeyPair> for KeyPair {
    fn from(value: devolutions_crypto::key::KeyPair) -> Self {
        Self {
            private_key: value.private_key.into(),
            public_key: value.public_key.into(),
        }
    }
}

pub fn generate_keypair(version: KeyVersion) -> KeyPair {
    devolutions_crypto::key::generate_keypair(version).into()
}

#[uniffi::export]
pub fn mix_key_exchange(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let private_key = private_key.try_into()?;
    let public_key = public_key.try_into()?;

    devolutions_crypto::key::mix_key_exchange(&private_key, &public_key)
}
