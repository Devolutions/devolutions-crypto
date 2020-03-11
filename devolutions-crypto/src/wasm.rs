use std::convert::TryFrom as _;

use base64;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use js_sys::{Array, Uint8Array};

use super::utils;
use super::DcDataBlob;
use super::DevoCryptoError;

use super::Argon2Parameters;
use super::DataType;

#[wasm_bindgen]
pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

#[cfg(target_arch = "wasm32")]
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

    #[wasm_bindgen]
    pub fn from(buffer: &[u8]) -> Result<Argon2Parameters, JsValue> {
        Ok(Self::try_from(buffer)?)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PublicKey {
    key: DcDataBlob,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PrivateKey {
    key: DcDataBlob,
}

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.key.clone().into()
    }

    #[wasm_bindgen]
    pub fn from(buffer: &[u8]) -> Result<PublicKey, JsValue> {
        let key = DcDataBlob::try_from(buffer)?;

        if key.header.data_type != DataType::Key || key.header.data_subtype != 2 {
            Err(DevoCryptoError::InvalidDataType)?
        };

        Ok(PublicKey { key })
    }
}

#[wasm_bindgen]
impl PrivateKey {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.key.clone().into()
    }

    #[wasm_bindgen]
    pub fn from(buffer: &[u8]) -> Result<PrivateKey, JsValue> {
        let key = DcDataBlob::try_from(buffer)?;

        if key.header.data_type != DataType::Key || key.header.data_subtype != 1 {
            Err(DevoCryptoError::InvalidDataType)?
        };

        Ok(PrivateKey { key })
    }
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

#[wasm_bindgen]
pub fn encrypt(data: &[u8], key: &[u8], version: Option<u16>) -> Result<Vec<u8>, JsValue> {
    Ok(DcDataBlob::encrypt(&data, &key, version)?.into())
}

#[wasm_bindgen(js_name = "encryptAsymmetric")]
pub fn encrypt_asymmetric(
    data: &[u8],
    public_key: PublicKey,
    version: Option<u16>,
) -> Result<Vec<u8>, JsValue> {
    Ok(DcDataBlob::encrypt_asymmetric(&data, &public_key.key, version)?.into())
}

#[wasm_bindgen]
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let data_blob = DcDataBlob::try_from(data)?;
    Ok(data_blob.decrypt(&key)?)
}

#[wasm_bindgen(js_name = "decryptAsymmetric")]
pub fn decrypt_asymmetric(data: &[u8], private_key: PrivateKey) -> Result<Vec<u8>, JsValue> {
    let data_blob = DcDataBlob::try_from(data)?;
    Ok(data_blob.decrypt_asymmetric(&private_key.key)?)
}

#[wasm_bindgen(js_name = "hashPassword")]
pub fn hash_password(password: &[u8], iterations: Option<u32>) -> Result<Vec<u8>, JsValue> {
    Ok(DcDataBlob::hash_password(&password, iterations.unwrap_or(10000))?.into())
}

#[wasm_bindgen(js_name = "verifyPassword")]
pub fn verify_password(password: &[u8], hash: &[u8]) -> Result<bool, JsValue> {
    let data_blob = DcDataBlob::try_from(hash)?;
    Ok(data_blob.verify_password(&password)?)
}

#[wasm_bindgen(js_name = "generateKeyPair")]
pub fn generate_key_pair() -> Result<KeyPair, JsValue> {
    let (private, public) = DcDataBlob::generate_key_exchange()?;

    let keypair = KeyPair {
        private_key: PrivateKey { key: private },
        public_key: PublicKey { key: public },
    };
    Ok(keypair)
}

#[wasm_bindgen(js_name = "mixKeyExchange")]
pub fn mix_key_exchange(
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<Vec<u8>, JsValue> {
    Ok(private_key.key.mix_key_exchange(&public_key.key)?)
}

#[wasm_bindgen(js_name = "deriveKeyPair")]
pub fn derive_keypair(password: &[u8], parameters: &Argon2Parameters) -> Result<KeyPair, JsValue> {
    let (private, public) = DcDataBlob::derive_keypair(password, parameters)?;

    let keypair = KeyPair {
        private_key: PrivateKey { key: private },
        public_key: PublicKey { key: public },
    };

    Ok(keypair)
}

#[wasm_bindgen(js_name = "generateSharedKey")]
pub fn generate_shared_key(
    n_shares: u8,
    threshold: u8,
    length: Option<usize>,
) -> Result<Array, JsValue> {
    DcDataBlob::generate_shared_key(n_shares, threshold, length.unwrap_or(32))?
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

#[wasm_bindgen(js_name = "joinShares")]
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
        .map(|x| DcDataBlob::try_from(x.as_slice()))
        .collect();
    Ok(DcDataBlob::join_shares(&shares?)?)
}

#[wasm_bindgen(js_name = "generateKey")]
pub fn generate_key(length: Option<usize>) -> Vec<u8> {
    utils::generate_key(length.unwrap_or(32))
}

#[wasm_bindgen(js_name = "deriveKey")]
pub fn derive_key(
    key: &[u8],
    salt: Option<Vec<u8>>,
    iterations: Option<usize>,
    length: Option<usize>,
) -> Vec<u8> {
    let salt = salt.unwrap_or(vec![0u8; 0]);
    let iterations = iterations.unwrap_or(10000);
    let length = length.unwrap_or(32);

    utils::derive_key(key, &salt, iterations, length)
}

#[wasm_bindgen]
pub fn base64encode(data: &[u8]) -> String {
    base64::encode(data)
}

#[wasm_bindgen]
pub fn base64decode(data: &str) -> Result<Vec<u8>, JsValue> {
    match base64::decode(&data) {
        Ok(res) => Ok(res),
        Err(e) => {
            let error = js_sys::Error::new(&format!("{}", e));
            error.set_name("Base64Error");
            Err(error.into())
        }
    }
}
