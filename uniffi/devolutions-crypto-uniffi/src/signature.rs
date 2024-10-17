use crate::Result;
use crate::SignatureVersion;

#[uniffi::export]
pub fn sign(data: &[u8], keypair: &[u8], version: Option<SignatureVersion>) -> Result<Vec<u8>> {
    let keypair = keypair.try_into()?;

    Ok(devolutions_crypto::signature::sign(data, &keypair, version.unwrap_or_default()).into())
}

#[uniffi::export]
pub fn verify_signature(data: &[u8], public_key: &[u8], signature: &[u8]) -> Result<bool> {
    let signature: devolutions_crypto::signature::Signature = signature.try_into()?;
    let public_key = public_key.try_into()?;

    Ok(signature.verify(data, &public_key))
}
