use std::sync::Arc;

use crate::{Argon2Parameters, Result};

#[derive(uniffi::Record)]
pub struct KeyDerivationResult {
    pub secret_key: Vec<u8>,
    pub parameters: Vec<u8>,
}

#[uniffi::export(default(iterations = 600000))]
pub fn derive_secret_key_pbkdf2(key: &[u8], iterations: u32) -> Result<KeyDerivationResult> {
    let (sk, params) =
        devolutions_crypto::key_derivation::Pbkdf2::with_params(iterations).derive(key)?;
    Ok(KeyDerivationResult {
        secret_key: sk.into(),
        parameters: params.into(),
    })
}

#[uniffi::export(default(iterations = 600000))]
pub fn derive_secret_key_pbkdf2_with_salt(
    key: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<KeyDerivationResult> {
    let (sk, params) = devolutions_crypto::key_derivation::Pbkdf2::with_params(iterations)
        .derive_with_salt(key, salt)?;
    Ok(KeyDerivationResult {
        secret_key: sk.into(),
        parameters: params.into(),
    })
}

#[uniffi::export]
pub fn derive_secret_key_argon2(
    key: &[u8],
    parameters: &Arc<Argon2Parameters>,
) -> Result<KeyDerivationResult> {
    let (sk, params) =
        devolutions_crypto::key_derivation::Argon2::with_params(parameters.inner.clone())
            .derive(key)?;
    Ok(KeyDerivationResult {
        secret_key: sk.into(),
        parameters: params.into(),
    })
}
