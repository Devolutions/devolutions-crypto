use std;
use std::convert::TryFrom;

use super::DevoCryptoError;
use super::Result;

mod dc_header;
mod dc_payload;

mod dc_ciphertext;
mod dc_hash;
mod dc_key;

pub use self::dc_header::DcHeader;
pub use self::dc_payload::DcPayload;

pub use self::dc_ciphertext::{DcCiphertext, CIPHERTEXT};
pub use self::dc_hash::{DcHash, HASH};
pub use self::dc_key::{DcKey, KEY};

pub struct DcDataBlob {
    header: DcHeader,
    payload: DcPayload,
}

impl TryFrom<&[u8]> for DcDataBlob {
    type Error = DevoCryptoError;
    fn try_from(data: &[u8]) -> Result<DcDataBlob> {
        let header = DcHeader::try_from(&data[0..8])?;
        let payload = DcPayload::try_from_header(&data[8..], &header)?;
        Ok(DcDataBlob { header, payload })
    }
}

impl Into<Vec<u8>> for DcDataBlob {
    fn into(self) -> Vec<u8> {
        let mut data: Vec<u8> = self.header.into();
        let mut payload: Vec<u8> = self.payload.into();
        data.append(&mut payload);
        data
    }
}

impl DcDataBlob {
    pub fn encrypt(data: &[u8], key: &[u8]) -> Result<DcDataBlob> {
        let mut header = DcHeader::new();
        let payload = DcPayload::encrypt(data, key, &mut header)?;
        Ok(DcDataBlob { header, payload })
    }

    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>> {
        self.payload.decrypt(key, &self.header)
    }

    pub fn hash_password(pass: &[u8], iterations: u32) -> Result<DcDataBlob> {
        let mut header = DcHeader::new();
        let payload = DcPayload::hash_password(pass, iterations, &mut header)?;
        Ok(DcDataBlob { header, payload })
    }

    pub fn verify_password(&self, pass: &[u8]) -> Result<bool> {
        self.payload.verify_password(pass)
    }

    pub fn generate_key_exchange() -> Result<(DcDataBlob, DcDataBlob)> {
        let mut header_private = DcHeader::new();
        let mut header_public = DcHeader::new();
        let (payload_private, payload_public) =
            DcPayload::generate_key_exchange(&mut header_private, &mut header_public)?;
        Ok((
            DcDataBlob {
                header: header_private,
                payload: payload_private,
            },
            DcDataBlob {
                header: header_public,
                payload: payload_public,
            },
        ))
    }

    pub fn mix_key_exchange(self, public: DcDataBlob) -> Result<Vec<u8>> {
        self.payload.mix_key_exchange(public.payload)
    }
}

#[test]
fn crypto_test() {
    let key = "0123456789abcdefghijkl".as_bytes();
    let data = "This is a very complex string of character that we need to encrypt".as_bytes();

    let encrypted = DcDataBlob::encrypt(data, key).unwrap();
    let decrypted = encrypted.decrypt(key).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn password_test() {
    let pass = "thisisaveryveryverystrongPa$$w0rd , //".as_bytes();
    let iterations = 1234u32;

    let hash = DcDataBlob::hash_password(pass, iterations).unwrap();

    assert!(hash.verify_password(pass).unwrap());
    assert!(!hash.verify_password("averybadpassword".as_bytes()).unwrap())
}

#[test]
fn ecdh_test() {
    let (bob_priv, bob_pub) = DcDataBlob::generate_key_exchange().unwrap();
    let (alice_priv, alice_pub) = DcDataBlob::generate_key_exchange().unwrap();

    let bob_shared = bob_priv.mix_key_exchange(alice_pub).unwrap();
    let alice_shared = alice_priv.mix_key_exchange(bob_pub).unwrap();

    assert_eq!(bob_shared, alice_shared);
}
