use crate::Result;
use crate::SignatureVersion;

pub fn sign(data: &[u8], keypair: &[u8], version: SignatureVersion) -> Result<Vec<u8>> {
    let keypair = keypair.try_into()?;

    Ok(devolutions_crypto::signature::sign(data, &keypair, version).into())
}

#[uniffi::export]
pub fn verify_signature(data: Vec<u8>, public_key: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
    let signature: devolutions_crypto::signature::Signature = signature.as_slice().try_into()?;
    let public_key = public_key.as_slice().try_into()?;

    Ok(signature.verify(data.as_slice(), &public_key))
}
