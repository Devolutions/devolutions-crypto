use wasm_bindgen::prelude::*;

use super::devocrypto;

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
    devocrypto::encrypt(&data, &key).unwrap()
}

#[wasm_bindgen]
pub fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    devocrypto::decrypt(&data, &key).unwrap()
}

#[wasm_bindgen]
pub fn hash_password(password: &[u8], niterations: u32) -> Vec<u8> {
    devocrypto::hash_password(&password, niterations).unwrap()
}

#[wasm_bindgen]
pub fn verify_password(password: &[u8], hash: &[u8]) -> bool {
    devocrypto::verify_password(&password, &hash).unwrap()
}

#[wasm_bindgen]
pub fn generate_key_exchange() -> KeyPair {
    let (public, private) = devocrypto::generate_key_exchange().unwrap();
    let pair = KeyPair { public_key: public, private_key: private };
    pair
}

#[wasm_bindgen]
pub fn mix_key_exchange(public: &[u8], private: &[u8]) -> Vec<u8> {
    devocrypto::mix_key_exchange(public, private).unwrap()
}

#[wasm_bindgen]
pub fn generate_key(length: usize) -> Vec<u8> {
    devocrypto::generate_key(length).unwrap()
}

#[wasm_bindgen]
pub fn derive_key(key: &[u8], salt: &[u8], niterations: usize, length: usize) -> Vec<u8> {
    devocrypto::derive_key(key, salt, niterations, length)
}