use crate::PasswordHashVersion;
use crate::Result;

#[uniffi::export(default(version = None))]
pub fn hash_password(password: Vec<u8>, version: Option<PasswordHashVersion>) -> Result<Vec<u8>> {
    let version = version.unwrap_or(PasswordHashVersion::Latest);
    Ok(devolutions_crypto::password_hash::hash_password(&password, version)?.into())
}

#[uniffi::export]
pub fn hash_password_with_params(password: Vec<u8>, params: Vec<u8>) -> Result<Vec<u8>> {
    let dp = devolutions_crypto::key_derivation::DerivationParameters::try_from(params.as_slice())?;
    Ok(devolutions_crypto::password_hash::hash_password_with_parameters(&password, dp)?.into())
}

#[uniffi::export]
pub fn verify_password(password: Vec<u8>, hash: Vec<u8>) -> Result<bool> {
    let hash: devolutions_crypto::password_hash::PasswordHash = hash.as_slice().try_into()?;
    Ok(hash.verify_password(&password))
}
