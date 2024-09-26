use crate::SigningKeyVersion;

#[derive(uniffi::Object)]
pub struct SigningKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl From<devolutions_crypto::signing_key::SigningKeyPair> for SigningKeyPair {
    fn from(value: devolutions_crypto::signing_key::SigningKeyPair) -> Self {
        let public_key = value.get_public_key();
        Self {
            private_key: value.into(),
            public_key: public_key.into(),
        }
    }
}

#[uniffi::export]
pub fn generate_signing_keypair(version: Option<SigningKeyVersion>) -> SigningKeyPair {
    devolutions_crypto::signing_key::generate_signing_keypair(version.unwrap_or_default()).into()
}
