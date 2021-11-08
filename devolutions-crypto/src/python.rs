use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict};

use std::convert::TryFrom;

use super::argon2parameters::Argon2Parameters;
use super::utils;
use super::Error;
use super::{ciphertext, ciphertext::Ciphertext};
use super::{
    key,
    key::{PrivateKey, PublicKey},
};
use super::{signature, signature::Signature};
use super::{
    signing_key,
    signing_key::{SigningKeyPair, SigningPublicKey},
};
use super::{CiphertextVersion, KeyVersion, SignatureVersion, SigningKeyVersion};

#[pymodule]
fn devolutions_crypto(_py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m)]
    #[pyo3(name = "encrypt")]
    fn encrypt(py: Python, data: &[u8], key: &[u8], version: Option<u16>) -> PyResult<Py<PyBytes>> {
        let version = match CiphertextVersion::try_from(version.unwrap_or(0)) {
            Ok(v) => v,
            Err(_) => {
                let error: PyErr = Error::UnknownVersion.into();
                return Err(error);
            }
        };

        let ciphertext: Vec<u8> = ciphertext::encrypt(data, key, version)?.into();
        Ok(PyBytes::new(py, &ciphertext).into())
    }

    #[pyfn(m)]
    #[pyo3(name = "encrypt_asymmetric")]
    fn encrypt_asymmetric(
        py: Python,
        data: &[u8],
        key: &[u8],
        version: Option<u16>,
    ) -> PyResult<Py<PyBytes>> {
        let version = match CiphertextVersion::try_from(version.unwrap_or(0)) {
            Ok(v) => v,
            Err(_) => {
                let error: PyErr = Error::UnknownVersion.into();
                return Err(error);
            }
        };

        let key = PublicKey::try_from(key)?;

        let ciphertext: Vec<u8> = ciphertext::encrypt_asymmetric(data, &key, version)?.into();
        Ok(PyBytes::new(py, &ciphertext).into())
    }

    #[pyfn(m)]
    #[pyo3(name = "decrypt")]
    fn decrypt(py: Python, data: &[u8], key: &[u8]) -> PyResult<Py<PyBytes>> {
        let ciphertext: Ciphertext = ciphertext::Ciphertext::try_from(data)?;
        let plaintext: Vec<u8> = ciphertext.decrypt(key)?.into();
        Ok(PyBytes::new(py, &plaintext).into())
    }

    #[pyfn(m)]
    #[pyo3(name = "decrypt_asymmetric")]
    fn decrypt_asymmetric(py: Python, data: &[u8], key: &[u8]) -> PyResult<Py<PyBytes>> {
        let ciphertext: Ciphertext = ciphertext::Ciphertext::try_from(data)?;
        let key: PrivateKey = PrivateKey::try_from(key)?;
        let plaintext: Vec<u8> = ciphertext.decrypt_asymmetric(&key)?.into();
        Ok(PyBytes::new(py, &plaintext).into())
    }

    #[pyfn(m)]
    #[pyo3(name = "derive_key_pbkdf2")]
    fn derive_key_pbkdf2(
        py: Python,
        key: &[u8],
        salt: Option<Vec<u8>>,
        iterations: Option<u32>,
        length: Option<usize>,
    ) -> PyResult<Py<PyBytes>> {
        let salt = salt.unwrap_or_else(|| vec![0u8; 0]);
        let iterations = iterations.unwrap_or(10000);
        let length = length.unwrap_or(32);

        let key = utils::derive_key_pbkdf2(key, &salt, iterations, length);
        Ok(PyBytes::new(py, &key).into())
    }

    #[pyfn(m)]
    #[pyo3(name = "derive_key_argon2")]
    fn derive_key_argon2(py: Python, key: &[u8], parameters: &[u8]) -> PyResult<Py<PyBytes>> {
        let parameters = Argon2Parameters::try_from(parameters)?;

        let key = utils::derive_key_argon2(key, &parameters)?;
        Ok(PyBytes::new(py, &key).into())
    }

    #[pyfn(m)]
    #[pyo3(name = "sign")]
    fn sign(
        py: Python,
        data: &[u8],
        keypair: &[u8],
        version: Option<u16>,
    ) -> PyResult<Py<PyBytes>> {
        let version = match SignatureVersion::try_from(version.unwrap_or(0)) {
            Ok(v) => v,
            Err(_) => {
                let error: PyErr = Error::UnknownVersion.into();
                return Err(error);
            }
        };

        let keypair = SigningKeyPair::try_from(keypair)?;

        let signature: Vec<u8> = signature::sign(data, &keypair, version).into();
        Ok(PyBytes::new(py, &signature).into())
    }

    #[pyfn(m)]
    #[pyo3(name = "verify_signature")]
    fn verify_signature(
        py: Python,
        data: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> PyResult<Py<PyBool>> {
        let public_key = SigningPublicKey::try_from(public_key)?;
        let signature = Signature::try_from(signature)?;

        Ok(PyBool::new(py, signature.verify(data, &public_key)).into())
    }

    #[pyfn(m)]
    #[pyo3(name = "generate_keypair")]
    fn generate_keypair(py: Python, version: Option<u16>) -> PyResult<Py<PyDict>> {
        let version = match KeyVersion::try_from(version.unwrap_or(0)) {
            Ok(v) => v,
            Err(_) => {
                let error: PyErr = Error::UnknownVersion.into();
                return Err(error);
            }
        };

        let kp = key::generate_keypair(version);

        let private_key: Vec<u8> = kp.private_key.into();
        let public_key: Vec<u8> = kp.public_key.into();

        let keypair = PyDict::new(py);
        keypair.set_item("private_key", PyBytes::new(py, &private_key))?;
        keypair.set_item("public_key", PyBytes::new(py, &public_key))?;
        Ok(keypair.into())
    }

    #[pyfn(m)]
    #[pyo3(name = "generate_signing_keypair")]
    fn generate_signing_keypair(py: Python, version: Option<u16>) -> PyResult<Py<PyBytes>> {
        let version = match SigningKeyVersion::try_from(version.unwrap_or(0)) {
            Ok(v) => v,
            Err(_) => {
                let error: PyErr = Error::UnknownVersion.into();
                return Err(error);
            }
        };

        let kp = signing_key::generate_signing_keypair(version);

        let kp: Vec<u8> = kp.into();

        Ok(PyBytes::new(py, &kp).into())
    }

    #[pyfn(m)]
    #[pyo3(name = "get_signing_public_key")]
    fn get_signing_public_key(py: Python, keypair: &[u8]) -> PyResult<Py<PyBytes>> {
        let keypair = SigningKeyPair::try_from(keypair)?;

        let public_key: Vec<u8> = keypair.get_public_key().into();

        Ok(PyBytes::new(py, &public_key).into())
    }

    Ok(())
}

impl From<Error> for PyErr {
    fn from(error: Error) -> PyErr {
        let description: String = error.to_string();
        let name: &str = error.into();
        exceptions::PyBaseException::new_err((name, description))
    }
}
