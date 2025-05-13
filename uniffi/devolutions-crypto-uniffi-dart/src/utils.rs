use std::sync::Arc;

use crate::{Argon2Parameters, DataType, Result};

#[uniffi::export]
pub fn generate_key(length: u32) -> Result<Vec<u8>> {
    devolutions_crypto::utils::generate_key(length as usize)
}

#[uniffi::export]
pub fn derive_key_pbkdf2(
    key: Vec<u8>,
    salt: Option<Vec<u8>>,
    iterations: u32,
    length: u32,
) -> Vec<u8> {
    devolutions_crypto::utils::derive_key_pbkdf2(
        key.as_slice(),
        &salt.unwrap_or_default(),
        iterations,
        length as usize,
    )
}

#[uniffi::export]
pub fn derive_key_argon2(key: Vec<u8>, parameters: &Arc<Argon2Parameters>) -> Result<Vec<u8>> {
    devolutions_crypto::utils::derive_key_argon2(key.as_slice(), &parameters.0)
}

#[uniffi::export]
pub fn validate_header(data: Vec<u8>, data_type: DataType) -> bool {
    devolutions_crypto::utils::validate_header(data.as_slice(), data_type)
}

#[uniffi::export]
pub fn base64_encode(data: Vec<u8>) -> String {
    devolutions_crypto::utils::base64_encode(data.as_slice())
}

#[uniffi::export]
pub fn base64_decode(data: &String) -> Result<Vec<u8>> {
    devolutions_crypto::utils::base64_decode(data)
}

#[uniffi::export]
pub fn base64_encode_url(data: Vec<u8>) -> String {
    devolutions_crypto::utils::base64_encode_url(data.as_slice())
}

#[uniffi::export]
pub fn base64_decode_url(data: &String) -> Result<Vec<u8>> {
    devolutions_crypto::utils::base64_decode_url(data)
}
