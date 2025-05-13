use crate::PasswordHashVersion;
use crate::Result;

pub fn hash_password(
    password: &[u8],
    iterations: u32,
    version: PasswordHashVersion,
) -> Result<Vec<u8>> {
    Ok(devolutions_crypto::password_hash::hash_password(password, iterations, version)?.into())
}

#[uniffi::export]
pub fn verify_password(password: Vec<u8>, hash: Vec<u8>) -> Result<bool> {
    let hash: devolutions_crypto::password_hash::PasswordHash = hash.as_slice().try_into()?;
    Ok(hash.verify_password(password.as_slice()))
}
