use crate::{CiphertextVersion, KeyDerivationVersion, Result};
use devolutions_crypto::derive_encrypt::KdfEncryptedData;
use devolutions_crypto::key_derivation::derive_key;

#[uniffi::export(default(kdf_version = None, ct_version = None))]
pub fn derive_encrypt_with_password(
    data: &[u8],
    password: &[u8],
    kdf_version: Option<KeyDerivationVersion>,
    ct_version: Option<CiphertextVersion>,
) -> Result<Vec<u8>> {
    let kdf_version = kdf_version.unwrap_or(KeyDerivationVersion::Latest);
    let ct_version = ct_version.unwrap_or(CiphertextVersion::Latest);
    let (_, params) = derive_key(password, kdf_version)?;
    Ok(devolutions_crypto::derive_encrypt::encrypt_with_password(
        data, password, params, ct_version,
    )?
    .into())
}

#[uniffi::export(default(kdf_version = None, ct_version = None))]
pub fn derive_encrypt_with_password_and_aad(
    data: &[u8],
    password: &[u8],
    aad: &[u8],
    kdf_version: Option<KeyDerivationVersion>,
    ct_version: Option<CiphertextVersion>,
) -> Result<Vec<u8>> {
    let kdf_version = kdf_version.unwrap_or(KeyDerivationVersion::Latest);
    let ct_version = ct_version.unwrap_or(CiphertextVersion::Latest);
    let (_, params) = derive_key(password, kdf_version)?;
    Ok(
        devolutions_crypto::derive_encrypt::encrypt_with_password_and_aad(
            data, password, aad, params, ct_version,
        )?
        .into(),
    )
}

#[uniffi::export]
pub fn derive_decrypt_with_password(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    KdfEncryptedData::try_from(data)?.decrypt_with_password(password)
}

#[uniffi::export]
pub fn derive_decrypt_with_password_and_aad(
    data: &[u8],
    password: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    KdfEncryptedData::try_from(data)?.decrypt_with_password_and_aad(password, aad)
}
