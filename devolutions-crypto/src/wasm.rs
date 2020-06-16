use std::convert::TryFrom as _;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use js_sys::{Array, Uint8Array};

use super::utils;

use super::{
    ciphertext,
    ciphertext::{Ciphertext, CiphertextVersion},
};
use super::{
    key,
    key::{KeyVersion, PrivateKey, PublicKey},
};
use super::{
    password_hash,
    password_hash::{PasswordHash, PasswordHashVersion},
};
use super::{
    secret_sharing,
    secret_sharing::{SecretSharingVersion, Share},
};

use super::Argon2Parameters;
use super::DataType;

// Local KeyPair have private fields with getters instead of public field, for wasm_bindgen
#[wasm_bindgen(inspectable)]
#[derive(Clone)]
pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter)]
    pub fn private(&self) -> PrivateKey {
        self.private_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> PublicKey {
        self.public_key.clone()
    }
}

impl From<key::KeyPair> for KeyPair {
    fn from(keypair: key::KeyPair) -> Self {
        Self {
            private_key: keypair.private_key,
            public_key: keypair.public_key,
        }
    }
}

impl From<KeyPair> for key::KeyPair {
    fn from(keypair: KeyPair) -> Self {
        Self {
            private_key: keypair.private_key,
            public_key: keypair.public_key,
        }
    }
}

#[wasm_bindgen]
impl Argon2Parameters {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.clone().into()
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(buffer: &[u8]) -> Result<Argon2Parameters, JsValue> {
        Ok(Self::try_from(buffer)?)
    }
}

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.clone().into()
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(buffer: &[u8]) -> Result<PublicKey, JsValue> {
        Ok(PublicKey::try_from(buffer)?)
    }
}

#[wasm_bindgen]
impl PrivateKey {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.clone().into()
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(buffer: &[u8]) -> Result<PrivateKey, JsValue> {
        Ok(PrivateKey::try_from(buffer)?)
    }
}

#[wasm_bindgen]
pub fn encrypt(
    data: &[u8],
    key: &[u8],
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>, JsValue> {
    Ok(ciphertext::encrypt(&data, &key, version.unwrap_or(CiphertextVersion::Latest))?.into())
}

#[wasm_bindgen(js_name = "encryptAsymmetric")]
pub fn encrypt_asymmetric(
    data: &[u8],
    public_key: PublicKey,
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>, JsValue> {
    Ok(ciphertext::encrypt_asymmetric(
        &data,
        &public_key,
        version.unwrap_or(CiphertextVersion::Latest),
    )?
    .into())
}

#[wasm_bindgen]
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let data_blob = Ciphertext::try_from(data)?;
    Ok(data_blob.decrypt(&key)?)
}

#[wasm_bindgen(js_name = "decryptAsymmetric")]
pub fn decrypt_asymmetric(data: &[u8], private_key: PrivateKey) -> Result<Vec<u8>, JsValue> {
    let data_blob = Ciphertext::try_from(data)?;
    Ok(data_blob.decrypt_asymmetric(&private_key)?)
}

#[wasm_bindgen(js_name = "hashPassword")]
pub fn hash_password(
    password: &[u8],
    iterations: Option<u32>,
    version: Option<PasswordHashVersion>,
) -> Vec<u8> {
    password_hash::hash_password(
        &password,
        iterations.unwrap_or(10000),
        version.unwrap_or(PasswordHashVersion::Latest),
    )
    .into()
}

#[wasm_bindgen(js_name = "verifyPassword")]
pub fn verify_password(password: &[u8], hash: &[u8]) -> Result<bool, JsValue> {
    let password_hash = PasswordHash::try_from(hash)?;
    Ok(password_hash.verify_password(&password))
}

#[wasm_bindgen(js_name = "generateKeyPair")]
pub fn generate_keypair(version: Option<KeyVersion>) -> KeyPair {
    key::generate_keypair(version.unwrap_or(KeyVersion::Latest)).into()
}

#[wasm_bindgen(js_name = "mixKeyExchange")]
pub fn mix_key_exchange(
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<Vec<u8>, JsValue> {
    Ok(key::mix_key_exchange(private_key, public_key)?)
}

#[wasm_bindgen(js_name = "deriveKeyPair")]
pub fn derive_keypair(
    password: &[u8],
    parameters: &Argon2Parameters,
    version: Option<KeyVersion>,
) -> Result<KeyPair, JsValue> {
    Ok(key::derive_keypair(password, parameters, version.unwrap_or(KeyVersion::Latest))?.into())
}

#[wasm_bindgen(typescript_custom_section)]
const TS_OVERRIDE_GENERATE_SHARED_KEY: &str = r#"/**
* @param {number} n_shares 
* @param {number} threshold 
* @param {number | undefined} length 
* @returns {Uint8Array[]} 
*/
export function generateSharedKey(n_shares: number, threshold: number, length?: number): Uint8Array[];"#;

#[wasm_bindgen(js_name = "generateSharedKey", skip_typescript)]
pub fn generate_shared_key(
    n_shares: u8,
    threshold: u8,
    length: Option<usize>,
    version: Option<SecretSharingVersion>,
) -> Result<Array, JsValue> {
    secret_sharing::generate_shared_key(
        n_shares,
        threshold,
        length.unwrap_or(32),
        version.unwrap_or(SecretSharingVersion::Latest),
    )?
    .into_iter()
    .map(|x| match JsValue::from_serde(&Into::<Vec<u8>>::into(x)) {
        Ok(s) => Ok(s),
        Err(e) => {
            let error = js_sys::Error::new(&format!("{}", e));
            error.set_name("SerializationError");
            Err(error.into())
        }
    })
    .collect()
}

#[wasm_bindgen(typescript_custom_section)]
const TS_OVERRIDE_JOIN_SHARES: &str = r#"/**
* @param {Uint8Array[]} shares 
* @returns {Uint8Array} 
*/
export function joinShares(shares: Uint8Array[]): Uint8Array;"#;

#[wasm_bindgen(js_name = "joinShares", skip_typescript)]
pub fn join_shares(shares: Array) -> Result<Vec<u8>, JsValue> {
    // Hack to accept both Array<Array<u8>> and Array<Uint8Array> from Javascript.
    // Issue linked here: https://github.com/rustwasm/wasm-bindgen/issues/2017
    let shares = JsValue::from(shares.map(&mut |s, _, _| {
        if JsCast::is_instance_of::<Uint8Array>(&s) {
            JsValue::from(Array::from(&s))
        } else {
            s
        }
    }));

    let shares: Vec<Vec<u8>> = match shares.into_serde() {
        Ok(s) => s,
        Err(e) => {
            let error = js_sys::Error::new(&format!("{}", e));
            error.set_name("DeserializationError");
            return Err(error.into());
        }
    };

    let shares: Result<Vec<_>, _> = shares
        .iter()
        .map(|x| Share::try_from(x.as_slice()))
        .collect();
    Ok(secret_sharing::join_shares(&shares?)?)
}

#[wasm_bindgen(js_name = "generateKey")]
pub fn generate_key(length: Option<usize>) -> Vec<u8> {
    utils::generate_key(length.unwrap_or(32))
}

#[wasm_bindgen(js_name = "deriveKeyPbkdf2")]
pub fn derive_key_pbkdf2(
    key: &[u8],
    salt: Option<Vec<u8>>,
    iterations: Option<u32>,
    length: Option<usize>,
) -> Vec<u8> {
    let salt = salt.unwrap_or_else(|| vec![0u8; 0]);
    let iterations = iterations.unwrap_or(10000);
    let length = length.unwrap_or(32);

    utils::derive_key_pbkdf2(key, &salt, iterations, length)
}

#[wasm_bindgen(js_name = "deriveKeyArgon2")]
pub fn derive_key_argon2(key: &[u8], parameters: &Argon2Parameters) -> Result<Vec<u8>, JsValue> {
    Ok(utils::derive_key_argon2(key, parameters)?)
}

#[wasm_bindgen(js_name = "validateHeader")]
pub fn validate_header(data: &[u8], data_type: DataType) -> bool {
    utils::validate_header(data, data_type)
}

/// Temporarly binded here for a specific use case, don't rely on this.
#[wasm_bindgen(js_name = "scryptSimple")]
pub fn scrypt_simple(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32) -> String {
    utils::scrypt_simple(password, salt, log_n, r, p)
}

#[wasm_bindgen]
pub fn base64encode(data: &[u8]) -> String {
    utils::base64_encode(data)
}

#[wasm_bindgen]
pub fn base64decode(data: &str) -> Result<Vec<u8>, JsValue> {
    Ok(utils::base64_decode(data)?)
}

#[wasm_bindgen(js_name = "base64urlEncode")]
pub fn base64url_encode(data: &[u8]) -> String {
    utils::base64_encode_url(data)
}

#[wasm_bindgen(js_name = "base64urlDecode")]
pub fn base64url_decode(data: &str) -> Result<Vec<u8>, JsValue> {
    Ok(utils::base64_decode_url(data)?)
}
