use crate::PasswordHashVersion;
use crate::Result;

pub fn hash_password(
    password: &[u8],
    iterations: u32,
    version: PasswordHashVersion,
) -> Vec<u8> {
    devolutions_crypto::password_hash::hash_password(
        password,
        iterations,
        version,
    )
    .into()
}

#[uniffi::export]
pub fn verify_password(password: &[u8], hash: &[u8]) -> Result<bool> {
    let hash: devolutions_crypto::password_hash::PasswordHash = hash.try_into()?;
    Ok(hash.verify_password(password))
}
