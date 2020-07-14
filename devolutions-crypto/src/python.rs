use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use std::convert::TryFrom;

use super::utils;
use super::CiphertextVersion;
use super::Error;
use super::KeyVersion;
use super::{ciphertext, ciphertext::Ciphertext};
use super::{
    key,
    key::{PrivateKey, PublicKey},
};

#[pymodule]
fn devolutions_crypto(_py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m, "encrypt")]
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

    #[pyfn(m, "encrypt_asymmetric")]
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

    #[pyfn(m, "decrypt")]
    fn decrypt(py: Python, data: &[u8], key: &[u8]) -> PyResult<Py<PyBytes>> {
        let ciphertext: Ciphertext = ciphertext::Ciphertext::try_from(data)?;
        let plaintext: Vec<u8> = ciphertext.decrypt(key)?.into();
        Ok(PyBytes::new(py, &plaintext).into())
    }

    #[pyfn(m, "decrypt_asymmetric")]
    fn decrypt_asymmetric(py: Python, data: &[u8], key: &[u8]) -> PyResult<Py<PyBytes>> {
        let ciphertext: Ciphertext = ciphertext::Ciphertext::try_from(data)?;
        let key: PrivateKey = PrivateKey::try_from(key)?;
        let plaintext: Vec<u8> = ciphertext.decrypt_asymmetric(&key)?.into();
        Ok(PyBytes::new(py, &plaintext).into())
    }

    #[pyfn(m, "derive_key_pbkdf2")]
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

    #[pyfn(m, "generate_keypair")]
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

    Ok(())
}

impl From<Error> for PyErr {
    fn from(error: Error) -> PyErr {
        let description: String = error.to_string();
        let name: &str = error.into();
        exceptions::BaseException::py_err((name, description))
    }
}
