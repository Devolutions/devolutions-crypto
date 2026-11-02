use crate::KeyEncapsulationVersion;
use crate::Result;
use devolutions_crypto::key::SecretKey;
use devolutions_crypto::key_encapsulation::EncapsulatedKey;

/// The result of an encapsulation: the blob to send to the recipient and the shared secret key.
#[derive(uniffi::Record)]
pub struct EncapsulationResult {
    pub encapsulated_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Encapsulates a fresh shared secret to a version 2 (X-Wing) public key.
#[uniffi::export(default(version = None))]
pub fn encapsulate(
    public_key: Vec<u8>,
    version: Option<KeyEncapsulationVersion>,
) -> Result<EncapsulationResult> {
    let version = version.unwrap_or(KeyEncapsulationVersion::Latest);
    let public_key = public_key.as_slice().try_into()?;
    let (encapsulated_key, secret_key) =
        devolutions_crypto::key_encapsulation::encapsulate(&public_key, version)?;

    Ok(EncapsulationResult {
        encapsulated_key: encapsulated_key.into(),
        secret_key: secret_key.into(),
    })
}

/// Recovers the shared secret key from an encapsulated key using a version 2 (X-Wing) private key.
/// A wrong private key does not fail: it yields a different secret.
#[uniffi::export]
pub fn decapsulate(private_key: Vec<u8>, encapsulated_key: Vec<u8>) -> Result<Vec<u8>> {
    let private_key = private_key.as_slice().try_into()?;
    let encapsulated_key = EncapsulatedKey::try_from(encapsulated_key.as_slice())?;
    let secret_key: SecretKey =
        devolutions_crypto::key_encapsulation::decapsulate(&private_key, &encapsulated_key)?;

    Ok(secret_key.into())
}
