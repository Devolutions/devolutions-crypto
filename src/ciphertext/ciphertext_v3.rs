//! Ciphertext V3: X-Wing (X25519 + ML-KEM-768) + HKDF-SHA-256 + XChaCha20Poly1305
//!
//! Wire format of the payload (after the header):
//! `X-Wing ciphertext (1120 bytes) || nonce (24 bytes) || XChaCha20Poly1305 ciphertext and tag`.
use super::{PrivateKey, PublicKey};

use super::Error;
use super::Header;
use super::Result;

use super::Ciphertext;
use super::ciphertext_v2::CiphertextV2Symmetric;

use crate::key::key_v2::{KEM_CIPHERTEXT_SIZE, KemCiphertext};

use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

/// HKDF-SHA-256 `info` label binding the X-Wing shared secret to asymmetric ciphertext V3.
/// Part of the wire format: changing it breaks decryption of existing data.
const HKDF_INFO: &[u8] = b"devolutions_crypto ciphertext_v3";

#[derive(Clone, Debug)]
pub struct CiphertextV3Asymmetric {
    kem_ciphertext: Box<KemCiphertext>,
    ciphertext: CiphertextV2Symmetric,
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for CiphertextV3Asymmetric {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let kem_ciphertext: [u8; KEM_CIPHERTEXT_SIZE] = Arbitrary::arbitrary(u)?;
        let ciphertext = CiphertextV2Symmetric::arbitrary(u)?;
        Ok(Self {
            kem_ciphertext: Box::new(KemCiphertext::from(kem_ciphertext)),
            ciphertext,
        })
    }
}

impl From<CiphertextV3Asymmetric> for Vec<u8> {
    fn from(cipher: CiphertextV3Asymmetric) -> Self {
        let mut data = cipher.kem_ciphertext.to_vec();
        let mut ciphertext: Vec<u8> = cipher.ciphertext.into();
        data.append(&mut ciphertext);
        data
    }
}

impl TryFrom<&[u8]> for CiphertextV3Asymmetric {
    type Error = Error;
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() <= KEM_CIPHERTEXT_SIZE {
            return Err(Error::InvalidLength);
        };

        let kem_ciphertext = KemCiphertext::try_from(&data[..KEM_CIPHERTEXT_SIZE])
            .map_err(|_| Error::InvalidLength)?;
        let ciphertext = CiphertextV2Symmetric::try_from(&data[KEM_CIPHERTEXT_SIZE..])?;

        Ok(Self {
            kem_ciphertext: Box::new(kem_ciphertext),
            ciphertext,
        })
    }
}

impl CiphertextV3Asymmetric {
    pub fn encrypt(
        data: &[u8],
        public_key: &PublicKey,
        aad: &[u8],
        header: &Header<Ciphertext>,
    ) -> Result<Self> {
        let (kem_ciphertext, key) = public_key.x_wing_encapsulate(HKDF_INFO)?;

        let ciphertext = CiphertextV2Symmetric::encrypt_with_derived_key(data, &key, aad, header)?;

        Ok(Self {
            kem_ciphertext,
            ciphertext,
        })
    }

    pub fn decrypt(
        &self,
        private_key: &PrivateKey,
        aad: &[u8],
        header: &Header<Ciphertext>,
    ) -> Result<Vec<u8>> {
        let key = private_key.x_wing_decapsulate(&self.kem_ciphertext, HKDF_INFO)?;

        self.ciphertext.decrypt_with_derived_key(&key, aad, header)
    }
}
