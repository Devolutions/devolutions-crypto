use crate::Result;
use crate::SecretSharingVersion;

#[uniffi::export]
pub fn generate_shared_key(
    n_shares: u8,
    threshold: u8,
    length: Option<u64>,
    version: Option<SecretSharingVersion>,
) -> Result<Vec<Vec<u8>>> {
    Ok(devolutions_crypto::secret_sharing::generate_shared_key(
        n_shares,
        threshold,
        length.unwrap_or(devolutions_crypto::DEFAULT_KEY_SIZE as u64) as usize,
        version.unwrap_or_default(),
    )?
    .into_iter()
    .map(|s| s.into())
    .collect())
}

#[uniffi::export]
pub fn join_shares(shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    let shares: Result<Vec<_>> = shares.iter().map(|s| s.as_slice().try_into()).collect();

    devolutions_crypto::secret_sharing::join_shares(&shares?)
}
