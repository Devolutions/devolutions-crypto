use std::convert::TryFrom as _;

use base64;
use wasm_bindgen::prelude::*;

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
pub fn encrypt(data: &[u8], key: &[u8], version: Option<u16>) -> Result<Vec<u8>, JsValue> {
    let version = version.unwrap_or(0);
    Ok(DcDataBlob::encrypt(&data, &key, version)?.into())
}

#[wasm_bindgen]
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let data_blob = DcDataBlob::try_from(data)?;
    Ok(data_blob.decrypt(&key)?)
}

#[wasm_bindgen]
pub fn hash_password(password: &[u8], iterations: Option<u32>) -> Result<Vec<u8>, JsValue> {
    Ok(DcDataBlob::hash_password(&password, iterations.unwrap_or(10000))?.into())
}

#[wasm_bindgen]
pub fn verify_password(password: &[u8], hash: &[u8]) -> Result<bool, JsValue> {
    let data_blob = DcDataBlob::try_from(hash)?;
    Ok(data_blob.verify_password(&password)?)
}

#[wasm_bindgen]
pub fn generate_key_exchange() -> Result<KeyPair, JsValue> {
    let (private, public) = DcDataBlob::generate_key_exchange()?;
    let pair = KeyPair {
        private_key: private.into(),
        public_key: public.into(),
    };
    Ok(pair)
}

#[wasm_bindgen]
pub fn mix_key_exchange(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let private = DcDataBlob::try_from(private_key)?;
    let public = DcDataBlob::try_from(public_key)?;
    Ok(private.mix_key_exchange(public)?)
}

#[wasm_bindgen]
pub fn generate_key(length: Option<usize>) -> Result<Vec<u8>, JsValue> {
    Ok(utils::generate_key(length.unwrap_or(32))?)
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
pub fn base64decode(data: String) -> Result<Vec<u8>, JsValue> {
    match base64::decode(&data) {
        Ok(res) => Ok(res),
        Err(e) => {
            let error = js_sys::Error::new(&format!("{}", e));
            Err(error.into())
        }
    }
}
