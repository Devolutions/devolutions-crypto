use super::Argon2Parameters;

use super::DevoCryptoError;
use super::Result;

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct KeyV1Pair {
    pub private_key: KeyV1Private,
    pub public_key: KeyV1Public,
}

#[derive(Clone)]
pub struct KeyV1Private {
    key: StaticSecret,
}

#[derive(Clone)]
pub struct KeyV1Public {
    key: PublicKey,
}

impl From<KeyV1Private> for Vec<u8> {
    fn from(key: KeyV1Private) -> Self {
        key.key.to_bytes().to_vec()
    }
}

impl From<KeyV1Public> for Vec<u8> {
    fn from(key: KeyV1Public) -> Self {
        key.key.as_bytes().to_vec()
    }
}

impl From<&[u8]> for KeyV1Private {
    fn from(key: &[u8]) -> Self {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key[0..32]);
        Self {
            key: StaticSecret::from(key_bytes),
        }
    }
}

impl From<&[u8]> for KeyV1Public {
    fn from(key: &[u8]) -> Self {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key[0..32]);
        Self {
            key: PublicKey::from(key_bytes),
        }
    }
}

pub fn generate_keypair() -> KeyV1Pair {
    let private = StaticSecret::new(&mut OsRng);
    let public = PublicKey::from(&private);

    KeyV1Pair {
        private_key: KeyV1Private { key: private },
        public_key: KeyV1Public { key: public },
    }
}

pub fn derive_keypair(password: &[u8], parameters: &Argon2Parameters) -> Result<KeyV1Pair> {
    if parameters.length != 32 {
        return Err(DevoCryptoError::InvalidLength);
    }
    let mut derived_pass = parameters.compute(password)?;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&derived_pass[0..32]);

    derived_pass.zeroize();

    let private = StaticSecret::from(key_bytes);
    let public = PublicKey::from(&private);

    Ok(KeyV1Pair {
        private_key: KeyV1Private { key: private },
        public_key: KeyV1Public { key: public },
    })
}

pub fn mix_key_exchange(private: &KeyV1Private, public: &KeyV1Public) -> Vec<u8> {
    private.key.diffie_hellman(&public.key).as_bytes().to_vec()
}

impl From<&KeyV1Public> for x25519_dalek::PublicKey {
    fn from(data: &KeyV1Public) -> Self {
        data.key
    }
}

impl From<&KeyV1Private> for x25519_dalek::StaticSecret {
    fn from(data: &KeyV1Private) -> Self {
        data.key.clone()
    }
}
