use crate::{Argon2Parameters, DataType, Result};

#[uniffi::export]
pub fn generate_key(length: Option<u64>) -> Vec<u8> {
    devolutions_crypto::utils::generate_key(
        length.unwrap_or(devolutions_crypto::DEFAULT_KEY_SIZE as u64) as usize,
    )
}

#[uniffi::export]
pub fn derive_key_pbkdf2(
    key: &[u8],
    salt: Option<Vec<u8>>,
    iterations: Option<u32>,
    length: Option<u64>,
) -> Vec<u8> {
    devolutions_crypto::utils::derive_key_pbkdf2(
        key,
        &salt.unwrap_or_default(),
        iterations.unwrap_or(devolutions_crypto::DEFAULT_PBKDF2_ITERATIONS),
        length.unwrap_or(devolutions_crypto::DEFAULT_KEY_SIZE as u64) as usize,
    )
}

#[uniffi::export]
pub fn derive_key_argon2(key: &[u8], parameters: &Argon2Parameters) -> Result<Vec<u8>> {
    devolutions_crypto::utils::derive_key_argon2(key, &parameters.0)
}

#[uniffi::export]
pub fn validate_header(data: &[u8], data_type: DataType) -> bool {
    devolutions_crypto::utils::validate_header(data, data_type)
}

#[uniffi::export]
pub fn base64_encode(data: &[u8]) -> String {
    devolutions_crypto::utils::base64_encode(data)
}

#[uniffi::export]
pub fn base64_decode(data: &str) -> Result<Vec<u8>> {
    devolutions_crypto::utils::base64_decode(data)
}

#[uniffi::export]
pub fn base64_encode_url(data: &[u8]) -> String {
    devolutions_crypto::utils::base64_encode_url(data)
}

#[uniffi::export]
pub fn base64_decode_url(data: &str) -> Result<Vec<u8>> {
    devolutions_crypto::utils::base64_decode_url(data)
}
