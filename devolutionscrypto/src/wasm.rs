use std::convert::TryFrom as _;

use wasm_bindgen::prelude::*;

use super::devocrypto;
use super::DcDataBlob;

#[wasm_bindgen]
pub struct KeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPair {
    pub fn public(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn private(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

#[wasm_bindgen]
pub fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    DcDataBlob::encrypt(&data, &key).unwrap().into()
}

#[wasm_bindgen]
pub fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let data_blob = DcDataBlob::try_from(data).unwrap();
    data_blob.decrypt(&key).unwrap()
}

#[wasm_bindgen]
pub fn hash_password(password: &[u8], iterations: u32) -> Vec<u8> {
    DcDataBlob::hash_password(&password, iterations).unwrap().into()
}

#[wasm_bindgen]
pub fn verify_password(password: &[u8], hash: &[u8]) -> bool {
    let data_blob = DcDataBlob::try_from(hash).unwrap();
    data_blob.verify_password(&password).unwrap()
}

#[wasm_bindgen]
pub fn generate_key_exchange() -> KeyPair {
    let (private, public) = DcDataBlob::generate_key_exchange().unwrap();
    let pair = KeyPair { private_key: private.into(), public_key: public.into() };
    pair
}

#[wasm_bindgen]
pub fn mix_key_exchange(private: &[u8], public: &[u8]) -> Vec<u8> {
    let private = DcDataBlob::try_from(private).unwrap();
    let public = DcDataBlob::try_from(public).unwrap();
    private.mix_key_exchange(public).unwrap()
}

#[wasm_bindgen]
pub fn generate_key(length: usize) -> Vec<u8> {
    devocrypto::generate_key(length).unwrap()
}

#[wasm_bindgen]
pub fn derive_key(key: &[u8], salt: &[u8], iterations: usize, length: usize) -> Vec<u8> {
    devocrypto::derive_key(key, salt, iterations, length)
}