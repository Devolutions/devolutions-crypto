/// Ciphertext V2: XChaCha20Poly1305
use super::{PrivateKey, PublicKey};

use super::Error;
use super::Header;
use super::Result;

use super::Ciphertext;

use std::convert::TryFrom;

use aead::{
    generic_array::{typenum, GenericArray},
    Aead, NewAead, Payload,
};
use chacha20poly1305::XChaCha20Poly1305;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[derive(Zeroize, Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[zeroize(drop)]
pub struct CiphertextV2Symmetric {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CiphertextV2Asymmetric {
    public_key: x25519_dalek::PublicKey,
    ciphertext: CiphertextV2Symmetric,
}

#[cfg(feature = "fuzz")]
impl Arbitrary for CiphertextV2Asymmetric {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let public_key: [u8; 32] = Arbitrary::arbitrary(u)?;
        let public_key = x25519_dalek::PublicKey::from(public_key);
        let ciphertext = CiphertextV2Symmetric::arbitrary(u)?;
        Ok(Self {
            public_key,
            ciphertext,
        })
    }
}

impl From<CiphertextV2Symmetric> for Vec<u8> {
    fn from(mut cipher: CiphertextV2Symmetric) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&cipher.nonce);
        data.append(&mut cipher.ciphertext);
        data
    }
}

impl TryFrom<&[u8]> for CiphertextV2Symmetric {
    type Error = Error;
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() <= 24 {
            return Err(Error::InvalidLength);
        };

        let mut nonce = [0u8; 24];
        let mut ciphertext = vec![0u8; data.len() - 24];

        nonce.copy_from_slice(&data[0..24]);
        ciphertext.copy_from_slice(&data[24..]);

        Ok(CiphertextV2Symmetric { nonce, ciphertext })
    }
}

impl CiphertextV2Symmetric {
    fn derive_key(secret: &[u8]) -> GenericArray<u8, typenum::U32> {
        let mut hasher = Sha256::new();
        hasher.input(secret);
        hasher.result()
    }

    pub fn encrypt(data: &[u8], key: &[u8], header: &Header<Ciphertext>) -> Result<Self> {
        // Derive key
        let mut key = CiphertextV2Symmetric::derive_key(&key);

        // Generate nonce
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        // Authenticate the header
        let aad: Vec<u8> = (*header).clone().into();
        let payload = Payload {
            msg: data,
            aad: &aad,
        };

        // Encrypt
        let cipher = XChaCha20Poly1305::new(key);
        let ciphertext = cipher.encrypt(&GenericArray::from_slice(&nonce), payload)?;

        // Zero out the key
        key.zeroize();

        Ok(CiphertextV2Symmetric { nonce, ciphertext })
    }

    pub fn decrypt(&self, key: &[u8], header: &Header<Ciphertext>) -> Result<Vec<u8>> {
        // Derive key
        let mut key = CiphertextV2Symmetric::derive_key(&key);

        // Authenticate the header
        let aad: Vec<u8> = (*header).clone().into();
        let payload = Payload {
            msg: self.ciphertext.as_slice(),
            aad: &aad,
        };

        // Decrypt
        let cipher = XChaCha20Poly1305::new(key);
        let result = cipher.decrypt(&GenericArray::from_slice(&self.nonce), payload)?;

        // Zeroize the key
        key.zeroize();

        Ok(result)
    }
}

impl From<CiphertextV2Asymmetric> for Vec<u8> {
    fn from(cipher: CiphertextV2Asymmetric) -> Self {
        let mut data = Vec::new();
        let mut public_key = cipher.public_key.as_bytes().to_vec();
        let mut ciphertext = cipher.ciphertext.into();
        data.append(&mut public_key);
        data.append(&mut ciphertext);
        data
    }
}

impl TryFrom<&[u8]> for CiphertextV2Asymmetric {
    type Error = Error;
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() <= 32 {
            return Err(Error::InvalidLength);
        };

        let mut public_key = [0u8; 32];

        public_key.copy_from_slice(&data[0..32]);
        let ciphertext = CiphertextV2Symmetric::try_from(&data[32..])?;

        Ok(CiphertextV2Asymmetric {
            public_key: x25519_dalek::PublicKey::from(public_key),
            ciphertext,
        })
    }
}

impl CiphertextV2Asymmetric {
    pub fn encrypt(
        data: &[u8],
        public_key: &PublicKey,
        header: &Header<Ciphertext>,
    ) -> Result<Self> {
        let public_key = x25519_dalek::PublicKey::from(public_key);

        let ephemeral_private_key = StaticSecret::new(&mut OsRng);
        let ephemeral_public_key = x25519_dalek::PublicKey::from(&ephemeral_private_key);

        let key = ephemeral_private_key.diffie_hellman(&public_key);

        let ciphertext = CiphertextV2Symmetric::encrypt(data, key.as_bytes(), header)?;

        Ok(Self {
            public_key: ephemeral_public_key,
            ciphertext,
        })
    }

    pub fn decrypt(
        &self,
        private_key: &PrivateKey,
        header: &Header<Ciphertext>,
    ) -> Result<Vec<u8>> {
        let private_key = StaticSecret::from(private_key);

        let key = private_key.diffie_hellman(&self.public_key);

        self.ciphertext.decrypt(key.as_bytes(), header)
    }
}
