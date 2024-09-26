use crate::PasswordHashVersion;
use crate::Result;

#[uniffi::export]
pub fn hash_password(
    password: &[u8],
    iterations: Option<u32>,
    version: Option<PasswordHashVersion>,
) -> Vec<u8> {
    devolutions_crypto::password_hash::hash_password(
        password,
        iterations.unwrap_or(devolutions_crypto::DEFAULT_PBKDF2_ITERATIONS),
        version.unwrap_or_default(),
    )
    .into()
}

#[uniffi::export]
pub fn verify_password(password: &[u8], hash: &[u8]) -> Result<bool> {
    let hash: devolutions_crypto::password_hash::PasswordHash = hash.try_into()?;
    Ok(hash.verify_password(password))
}
