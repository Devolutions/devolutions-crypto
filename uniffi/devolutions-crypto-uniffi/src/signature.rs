use crate::Result;
use crate::SignatureVersion;

#[uniffi::export(default(version = None))]
pub fn sign(data: Vec<u8>, keypair: Vec<u8>, version: Option<SignatureVersion>) -> Result<Vec<u8>> {
    let version = version.unwrap_or(SignatureVersion::Latest);
    let keypair = keypair.as_slice().try_into()?;

    Ok(devolutions_crypto::signature::sign(&data, &keypair, version).into())
}

#[uniffi::export]
pub fn verify_signature(data: Vec<u8>, public_key: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
    let signature: devolutions_crypto::signature::Signature = signature.as_slice().try_into()?;
    let public_key = public_key.as_slice().try_into()?;

    Ok(signature.verify(&data, &public_key))
}
