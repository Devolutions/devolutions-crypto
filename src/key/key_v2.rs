//! Key V2: X-Wing hybrid KEM (X25519 + ML-KEM-768)
//!
//! The raw X-Wing shared secret never leaves this module: every encapsulation or
//! decapsulation goes through HKDF-SHA-256 with a caller-supplied, use-specific label.
use super::Error;
use super::Result;

use hkdf::Hkdf;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::Sha256;
use x_wing::{
    DecapsulationKeyRejectNonContrib, Decapsulator, EncapsulationKey, KeyExport, KeyInit,
    TryDecapsulate,
};
use zeroize::Zeroizing;

use std::convert::TryFrom;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

/// Serialized size of an X-Wing private (decapsulation) key: a 32-byte seed.
pub const PRIVATE_KEY_SIZE: usize = x_wing::DECAPSULATION_KEY_SIZE;
/// Serialized size of an X-Wing public (encapsulation) key: ML-KEM-768 (1184) || X25519 (32).
pub const PUBLIC_KEY_SIZE: usize = x_wing::ENCAPSULATION_KEY_SIZE;
/// Size of an X-Wing KEM ciphertext: ML-KEM-768 (1088) || X25519 (32).
pub const KEM_CIPHERTEXT_SIZE: usize = x_wing::CIPHERTEXT_SIZE;

/// Raw X-Wing KEM ciphertext.
pub type KemCiphertext = x_wing::Ciphertext;

#[derive(Clone)]
pub struct KeyV2Pair {
    pub private_key: KeyV2Private,
    pub public_key: KeyV2Public,
}

/// Rejects ciphertexts whose X25519 component is non-contributory (low-order point),
/// matching the behaviour of the X25519-based V1 keys.
#[derive(Clone)]
pub struct KeyV2Private {
    key: Box<DecapsulationKeyRejectNonContrib>,
}

impl core::fmt::Debug for KeyV2Private {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> std::result::Result<(), core::fmt::Error> {
        write!(f, "Private Key")
    }
}

#[derive(Clone, Debug)]
pub struct KeyV2Public {
    key: Box<EncapsulationKey>,
}

impl KeyV2Private {
    fn from_seed(seed: &[u8]) -> Result<Self> {
        let key = DecapsulationKeyRejectNonContrib::new_from_slice(seed)
            .map_err(|_| Error::InvalidLength)?;
        Ok(Self { key: Box::new(key) })
    }

    fn public_key(&self) -> KeyV2Public {
        KeyV2Public {
            key: Box::new(self.key.encapsulation_key().clone()),
        }
    }

    /// Decapsulates `ciphertext` and derives a 32-byte key from the shared secret with
    /// HKDF-SHA-256 (no salt) using `info` as the label.
    pub fn decapsulate(
        &self,
        ciphertext: &KemCiphertext,
        info: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let shared_secret = Zeroizing::new(
            self.key
                .try_decapsulate(ciphertext)
                .map_err(|_| Error::InvalidData)?,
        );

        Ok(derive_key(shared_secret.as_slice(), info))
    }
}

impl KeyV2Public {
    /// Encapsulates a fresh shared secret to this key and derives a 32-byte key from it with
    /// HKDF-SHA-256 (no salt) using `info` as the label.
    ///
    /// Returns `Error::RandomError` if the OS random number generator is unavailable.
    pub fn encapsulate(&self, info: &[u8]) -> Result<(Box<KemCiphertext>, Zeroizing<[u8; 32]>)> {
        let mut randomness = Zeroizing::new([0u8; x_wing::ENCAPSULATION_RANDOMNESS_SIZE]);
        SysRng
            .try_fill_bytes(randomness.as_mut_slice())
            .map_err(|_| Error::RandomError)?;

        let (ciphertext, shared_secret) = self.key.encapsulate_deterministic((&*randomness).into());
        let shared_secret = Zeroizing::new(shared_secret);

        Ok((
            Box::new(ciphertext),
            derive_key(shared_secret.as_slice(), info),
        ))
    }
}

fn derive_key(shared_secret: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, shared_secret)
        .expand(info, okm.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    okm
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for KeyV2Private {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed: [u8; PRIVATE_KEY_SIZE] = Arbitrary::arbitrary(u)?;
        Ok(Self::from_seed(&seed).expect("seed length is hardcoded and correct"))
    }
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for KeyV2Public {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(KeyV2Private::arbitrary(u)?.public_key())
    }
}

impl From<KeyV2Private> for Vec<u8> {
    fn from(key: KeyV2Private) -> Self {
        Zeroizing::new(key.key.to_bytes()).to_vec()
    }
}

impl From<KeyV2Public> for Vec<u8> {
    fn from(key: KeyV2Public) -> Self {
        key.key.to_bytes().to_vec()
    }
}

impl TryFrom<&[u8]> for KeyV2Private {
    type Error = Error;

    fn try_from(key: &[u8]) -> Result<Self> {
        if key.len() != PRIVATE_KEY_SIZE {
            return Err(Error::InvalidLength);
        }

        Self::from_seed(key)
    }
}

impl TryFrom<&[u8]> for KeyV2Public {
    type Error = Error;

    fn try_from(key: &[u8]) -> Result<Self> {
        if key.len() != PUBLIC_KEY_SIZE {
            return Err(Error::InvalidLength);
        }

        // Rejects ML-KEM encapsulation keys that fail the FIPS 203 modulus check.
        let encapsulation_key = EncapsulationKey::try_from(key).map_err(|_| Error::InvalidData)?;

        // Like V1 keys, reject a low-order X25519 component (the last 32 bytes), which would make
        // the X25519 half of the hybrid contribute nothing. With a clamped scalar (a multiple of 8),
        // the X25519 output is all-zero exactly when the point is of low order.
        let mut x25519_public = [0u8; 32];
        x25519_public.copy_from_slice(&key[PUBLIC_KEY_SIZE - 32..]);
        if !x25519_dalek::StaticSecret::from([1u8; 32])
            .diffie_hellman(&x25519_dalek::PublicKey::from(x25519_public))
            .was_contributory()
        {
            return Err(Error::InvalidData);
        }

        Ok(Self {
            key: Box::new(encapsulation_key),
        })
    }
}

pub fn generate_keypair() -> KeyV2Pair {
    let seed = crate::utils::random_bytes::<PRIVATE_KEY_SIZE>()
        .expect("the OS entropy source should be available");
    let private_key =
        KeyV2Private::from_seed(seed.as_slice()).expect("seed length is hardcoded and correct");
    let public_key = private_key.public_key();

    KeyV2Pair {
        private_key,
        public_key,
    }
}
