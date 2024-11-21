use crate::CiphertextVersion;
use crate::Result;

pub fn encrypt(data: &[u8], key: &[u8], version: CiphertextVersion) -> Result<Vec<u8>> {
    Ok(devolutions_crypto::ciphertext::encrypt(data, key, version)?.into())
}

pub fn encrypt_with_aad(
    data: &[u8],
    key: &[u8],
    aad: &[u8],
    version: CiphertextVersion,
) -> Result<Vec<u8>> {
    Ok(devolutions_crypto::ciphertext::encrypt_with_aad(data, key, aad, version)?.into())
}

#[uniffi::export]
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data)?;
    data.decrypt(key)
}

#[uniffi::export]
fn decrypt_with_aad(data: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data)?;
    data.decrypt_with_aad(key, aad)
}

pub fn encrypt_asymmetric(data: &[u8], key: &[u8], version: CiphertextVersion) -> Result<Vec<u8>> {
    let key = key.try_into()?;
    Ok(devolutions_crypto::ciphertext::encrypt_asymmetric(data, &key, version)?.into())
}

pub fn encrypt_asymmetric_with_aad(
    data: &[u8],
    key: &[u8],
    aad: &[u8],
    version: CiphertextVersion,
) -> Result<Vec<u8>> {
    let key = key.try_into()?;
    Ok(
        devolutions_crypto::ciphertext::encrypt_asymmetric_with_aad(data, &key, aad, version)?
            .into(),
    )
}

#[uniffi::export]
pub fn decrypt_asymmetric(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let key = key.try_into()?;
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data)?;
    data.decrypt_asymmetric(&key)
}

#[uniffi::export]
fn decrypt_asymmetric_with_aad(data: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = key.try_into()?;
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data)?;
    data.decrypt_asymmetric_with_aad(&key, aad)
}
