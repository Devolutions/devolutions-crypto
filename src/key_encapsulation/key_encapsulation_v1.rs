//! Key encapsulation V1: X-Wing (X25519 + ML-KEM-768) + HKDF-SHA-256
//!
//! Wire format of the payload (after the header): `X-Wing ciphertext (1120 bytes)`.
use super::Error;
use super::Result;

use super::{PrivateKey, PublicKey, SecretKey};

use crate::key::key_v2::{KEM_CIPHERTEXT_SIZE, KemCiphertext};
use crate::key::secret_key_from_raw;

use std::convert::TryFrom;

use zeroize::Zeroizing;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

/// HKDF-SHA-256 `info` label binding the X-Wing shared secret to key encapsulation V1.
/// Distinct from the ciphertext V3 label so a V3 ciphertext's KEM bytes never decapsulate to its AEAD key.
/// Part of the wire format: changing it breaks decapsulation of existing data.
const HKDF_INFO: &[u8] = b"devolutions_crypto key_encapsulation_v1";

#[derive(Clone, Debug)]
pub struct EncapsulatedKeyV1 {
    kem_ciphertext: Box<KemCiphertext>,
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for EncapsulatedKeyV1 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let kem_ciphertext: [u8; KEM_CIPHERTEXT_SIZE] = Arbitrary::arbitrary(u)?;
        Ok(Self {
            kem_ciphertext: Box::new(KemCiphertext::from(kem_ciphertext)),
        })
    }
}

impl EncapsulatedKeyV1 {
    pub fn encapsulate(public_key: &PublicKey) -> Result<(Self, SecretKey)> {
        let (kem_ciphertext, key) = public_key.x_wing_encapsulate(HKDF_INFO)?;
        let secret_key = secret_key_from_raw(Zeroizing::new(key.to_vec()))?;

        Ok((Self { kem_ciphertext }, secret_key))
    }

    pub fn decapsulate(&self, private_key: &PrivateKey) -> Result<SecretKey> {
        let key = private_key.x_wing_decapsulate(&self.kem_ciphertext, HKDF_INFO)?;
        secret_key_from_raw(Zeroizing::new(key.to_vec()))
    }
}

impl From<EncapsulatedKeyV1> for Vec<u8> {
    fn from(data: EncapsulatedKeyV1) -> Self {
        data.kem_ciphertext.to_vec()
    }
}

impl TryFrom<&[u8]> for EncapsulatedKeyV1 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() != KEM_CIPHERTEXT_SIZE {
            return Err(Error::InvalidLength);
        }

        let kem_ciphertext = KemCiphertext::try_from(data).map_err(|_| Error::InvalidLength)?;

        Ok(Self {
            kem_ciphertext: Box::new(kem_ciphertext),
        })
    }
}
