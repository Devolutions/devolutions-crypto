use crate::CiphertextVersion;
use crate::Result;
use devolutions_crypto::key::SecretKey;

#[uniffi::export(default(version = None))]
pub fn encrypt(data: Vec<u8>, key: Vec<u8>, version: Option<CiphertextVersion>) -> Result<Vec<u8>> {
    let version = version.unwrap_or(CiphertextVersion::Latest);
    Ok(devolutions_crypto::ciphertext::encrypt(&data, &key, version)?.into())
}

#[uniffi::export(default(version = None))]
pub fn encrypt_with_aad(
    data: Vec<u8>,
    key: Vec<u8>,
    aad: Vec<u8>,
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>> {
    let version = version.unwrap_or(CiphertextVersion::Latest);
    Ok(devolutions_crypto::ciphertext::encrypt_with_aad(&data, &key, &aad, version)?.into())
}

#[uniffi::export]
pub fn decrypt(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice())?;
    data.decrypt(&key)
}

#[uniffi::export]
fn decrypt_with_aad(data: Vec<u8>, key: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>> {
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice())?;
    data.decrypt_with_aad(&key, &aad)
}

#[uniffi::export(default(version = None))]
pub fn encrypt_asymmetric(
    data: Vec<u8>,
    key: Vec<u8>,
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>> {
    let version = version.unwrap_or(CiphertextVersion::Latest);
    let key = key.as_slice().try_into()?;
    Ok(devolutions_crypto::ciphertext::encrypt_asymmetric(&data, &key, version)?.into())
}

#[uniffi::export(default(version = None))]
pub fn encrypt_asymmetric_with_aad(
    data: Vec<u8>,
    key: Vec<u8>,
    aad: Vec<u8>,
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>> {
    let version = version.unwrap_or(CiphertextVersion::Latest);
    let key = key.as_slice().try_into()?;
    Ok(
        devolutions_crypto::ciphertext::encrypt_asymmetric_with_aad(&data, &key, &aad, version)?
            .into(),
    )
}

#[uniffi::export]
pub fn decrypt_asymmetric(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    let key = key.as_slice().try_into()?;
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice())?;
    data.decrypt_asymmetric(&key)
}

#[uniffi::export]
fn decrypt_asymmetric_with_aad(data: Vec<u8>, key: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>> {
    let key = key.as_slice().try_into()?;
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice())?;
    data.decrypt_asymmetric_with_aad(&key, &aad)
}

#[uniffi::export(default(version = None))]
pub fn encrypt_with_secret_key(
    data: Vec<u8>,
    key: Vec<u8>,
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>> {
    let version = version.unwrap_or(CiphertextVersion::Latest);
    let key = SecretKey::try_from(key.as_slice())?;
    Ok(devolutions_crypto::ciphertext::encrypt_with_secret_key(&data, &key, version)?.into())
}

#[uniffi::export(default(version = None))]
pub fn encrypt_with_secret_key_and_aad(
    data: Vec<u8>,
    key: Vec<u8>,
    aad: Vec<u8>,
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>> {
    let version = version.unwrap_or(CiphertextVersion::Latest);
    let key = SecretKey::try_from(key.as_slice())?;
    Ok(
        devolutions_crypto::ciphertext::encrypt_with_secret_key_and_aad(
            &data, &key, &aad, version,
        )?
        .into(),
    )
}

#[uniffi::export]
pub fn decrypt_with_secret_key(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    let key = SecretKey::try_from(key.as_slice())?;
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice())?;
    data.decrypt_with_secret_key(&key)
}

#[uniffi::export]
pub fn decrypt_with_secret_key_and_aad(
    data: Vec<u8>,
    key: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>> {
    let key = SecretKey::try_from(key.as_slice())?;
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data.as_slice())?;
    data.decrypt_with_secret_key_and_aad(&key, &aad)
}
