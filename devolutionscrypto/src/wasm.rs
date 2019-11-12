use std::convert::TryFrom as _;

use wasm_bindgen::prelude::*;
use base64;

use super::utils;
use super::DcDataBlob;

use zeroize::Zeroize as _;

#[wasm_bindgen]
pub struct KeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPair {
    pub fn private(&self) -> Vec<u8> {
        self.private_key.clone()
    }
    pub fn public(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.public_key.zeroize();
    }
}

#[wasm_bindgen]
pub fn encrypt(data: &[u8], key: &[u8], version: Option<u16>) -> Vec<u8> {
    let version = version.unwrap_or(0);
    DcDataBlob::encrypt(&data, &key, version).unwrap().into()
}

#[wasm_bindgen]
pub fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let data_blob = DcDataBlob::try_from(data).unwrap();
    data_blob.decrypt(&key).unwrap()
}

#[wasm_bindgen]
pub fn hash_password(password: &[u8], iterations: Option<u32>) -> Vec<u8> {
    DcDataBlob::hash_password(&password, iterations.unwrap_or(10000)).unwrap().into()
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
pub fn mix_key_exchange(private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
    let private = DcDataBlob::try_from(private_key).unwrap();
    let public = DcDataBlob::try_from(public_key).unwrap();
    private.mix_key_exchange(public).unwrap()
}

#[wasm_bindgen]
pub fn generate_key(length: Option<usize>) -> Vec<u8> {
    utils::generate_key(length.unwrap_or(32)).unwrap()
}

#[wasm_bindgen]
pub fn derive_key(key: &[u8], salt: &[u8], iterations: usize, length: usize) -> Vec<u8> {
    utils::derive_key(key, salt, iterations, length)
}

#[wasm_bindgen]
pub fn base64encode(data: &[u8]) -> String {
    base64::encode(data)
}

#[wasm_bindgen]
pub fn base64decode(data: String) -> Vec<u8> {
    base64::decode(&data).unwrap()
}