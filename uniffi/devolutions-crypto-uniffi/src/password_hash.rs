use crate::PasswordHashVersion;
use crate::Result;

#[uniffi::export(default(iterations = 10000, version = None))]
pub fn hash_password(
    password: &[u8],
    iterations: u32,
    version: Option<PasswordHashVersion>,
) -> Result<Vec<u8>> {
    let version = version.unwrap_or(PasswordHashVersion::Latest);
    Ok(devolutions_crypto::password_hash::hash_password(password, iterations, version)?.into())
}

#[uniffi::export]
pub fn verify_password(password: &[u8], hash: &[u8]) -> Result<bool> {
    let hash: devolutions_crypto::password_hash::PasswordHash = hash.try_into()?;
    Ok(hash.verify_password(password))
}
