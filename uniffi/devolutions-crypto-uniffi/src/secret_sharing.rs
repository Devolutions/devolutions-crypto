use crate::Result;
use crate::SecretSharingVersion;

#[uniffi::export(default(length = 32, version = None))]
pub fn generate_shared_key(
    n_shares: u8,
    threshold: u8,
    length: u32,
    version: Option<SecretSharingVersion>,
) -> Result<Vec<Vec<u8>>> {
    let version = version.unwrap_or(SecretSharingVersion::Latest);
    Ok(devolutions_crypto::secret_sharing::generate_shared_key(
        n_shares,
        threshold,
        length as usize,
        version,
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
