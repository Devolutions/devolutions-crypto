use devolutions_crypto::CiphertextVersion;

use devolutions_crypto::Error as DevolutionsCryptoError;

#[uniffi::export]
pub fn generate_key(length: Option<u64>) -> Vec<u8> {
    devolutions_crypto::utils::generate_key(length.unwrap_or(32) as usize)
}

#[uniffi::export]
pub fn encrypt(
    data: &[u8],
    key: &[u8],
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>, DevolutionsCryptoError> {
    Ok(devolutions_crypto::ciphertext::encrypt(
        data,
        key,
        version.unwrap_or(CiphertextVersion::Latest),
    )?
    .into())
}

#[uniffi::export]
pub fn encrypt_with_aad(
    data: &[u8],
    key: &[u8],
    aad: &[u8],
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>, DevolutionsCryptoError> {
    Ok(devolutions_crypto::ciphertext::encrypt_with_aad(
        data,
        key,
        aad,
        version.unwrap_or(CiphertextVersion::Latest),
    )?
    .into())
}

#[uniffi::export]
pub fn decrypt(
    data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, DevolutionsCryptoError> {
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data)?;
    data.decrypt(key)
}

#[uniffi::export]
fn decrypt_with_aad(
    data: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DevolutionsCryptoError> {
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data)?;
    data.decrypt_with_aad(key, aad)
}

uniffi::include_scaffolding!("devolutions_crypto");
