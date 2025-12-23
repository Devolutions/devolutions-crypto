use pyo3::create_exception;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes};

use std::convert::TryFrom;

use devolutions_crypto::utils;
use devolutions_crypto::Argon2Parameters;
use devolutions_crypto::Error;
use devolutions_crypto::{ciphertext, ciphertext::Ciphertext};
use devolutions_crypto::{
    key,
    key::{PrivateKey, PublicKey},
};
use devolutions_crypto::{signature, signature::Signature};
use devolutions_crypto::{
    signing_key,
    signing_key::{SigningKeyPair, SigningPublicKey},
};
use devolutions_crypto::{CiphertextVersion, KeyVersion, SignatureVersion, SigningKeyVersion};

enum DevolutionsCryptoError {
    DevolutionsCrypto(Error),
    Python(PyErr),
}

create_exception!(
    devolutions_crypto,
    DevolutionsCryptoException,
    pyo3::exceptions::PyException
);

#[pyclass]
pub struct Keypair {
    #[pyo3(get)]
    pub public_key: Py<PyAny>,
    #[pyo3(get)]
    pub private_key: Py<PyAny>,
}

type Result<T> = std::result::Result<T, DevolutionsCryptoError>;

#[pyfunction]
#[pyo3(name = "encrypt")]
#[pyo3(signature = (data, key, aad=None, version=0))]
fn encrypt(
    py: Python,
    data: &[u8],
    key: &[u8],
    aad: Option<&[u8]>,
    version: u16,
) -> Result<Py<PyBytes>> {
    let version = match CiphertextVersion::try_from(version) {
        Ok(v) => v,
        Err(_) => {
            let error: DevolutionsCryptoError = Error::UnknownVersion.into();
            return Err(error);
        }
    };

    let ciphertext: Vec<u8> = match aad {
        Some(aad) => ciphertext::encrypt_with_aad(data, key, aad, version)?.into(),
        None => ciphertext::encrypt(data, key, version)?.into(),
    };

    Ok(PyBytes::new(py, &ciphertext).into())
}

#[pyfunction]
#[pyo3(name = "encrypt_asymmetric")]
#[pyo3(signature = (data, key, aad=None, version=0))]
fn encrypt_asymmetric(
    py: Python,
    data: &[u8],
    key: &[u8],
    aad: Option<&[u8]>,
    version: u16,
) -> Result<Py<PyBytes>> {
    let version = match CiphertextVersion::try_from(version) {
        Ok(v) => v,
        Err(_) => {
            let error: DevolutionsCryptoError = Error::UnknownVersion.into();
            return Err(error);
        }
    };

    let key = PublicKey::try_from(key)?;

    let ciphertext: Vec<u8> = match aad {
        Some(aad) => ciphertext::encrypt_asymmetric_with_aad(data, &key, aad, version)?.into(),
        None => ciphertext::encrypt_asymmetric(data, &key, version)?.into(),
    };

    Ok(PyBytes::new(py, &ciphertext).into())
}

#[pyfunction]
#[pyo3(name = "hash_password")]
#[pyo3(signature = (password, iterations=10000, version=0))]
fn hash_password(
    py: Python,
    password: &[u8],
    iterations: u32,
    version: u16,
) -> Result<Py<PyBytes>> {
    let version =
        match devolutions_crypto::password_hash::PasswordHashVersion::try_from(version) {
            Ok(v) => v,
            Err(_) => {
                let error: DevolutionsCryptoError = Error::UnknownVersion.into();
                return Err(error);
            }
        };

    let hash: Vec<u8> =
        devolutions_crypto::password_hash::hash_password(password, iterations, version)?.into();
    Ok(PyBytes::new(py, &hash).into())
}

#[pyfunction]
#[pyo3(name = "verify_password")]
fn verify_password(py: Python, password: &[u8], hash: &[u8]) -> Result<Py<PyBool>> {
    let res = devolutions_crypto::password_hash::PasswordHash::try_from(hash)?;

    Ok(PyBool::new(py, res.verify_password(password))
        .to_owned()
        .into())
}

#[pyfunction]
#[pyo3(name = "decrypt")]
#[pyo3(signature = (data, key, aad=None))]
fn decrypt(py: Python, data: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<Py<PyBytes>> {
    let ciphertext: Ciphertext = ciphertext::Ciphertext::try_from(data)?;
    let plaintext: Vec<u8> = match aad {
        Some(aad) => ciphertext.decrypt_with_aad(key, aad)?.into(),
        None => ciphertext.decrypt(key)?.into(),
    };

    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
#[pyo3(name = "decrypt_asymmetric")]
#[pyo3(signature = (data, key, aad=None))]
fn decrypt_asymmetric(
    py: Python,
    data: &[u8],
    key: &[u8],
    aad: Option<&[u8]>,
) -> Result<Py<PyBytes>> {
    let ciphertext: Ciphertext = ciphertext::Ciphertext::try_from(data)?;
    let key: PrivateKey = PrivateKey::try_from(key)?;
    let plaintext: Vec<u8> = match aad {
        Some(aad) => ciphertext.decrypt_asymmetric_with_aad(&key, aad)?.into(),
        None => ciphertext.decrypt_asymmetric(&key)?.into(),
    };

    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
#[pyo3(name = "derive_key_pbkdf2")]
#[pyo3(signature = (key, salt=None, iterations=10000, length=32))]
fn derive_key_pbkdf2(
    py: Python,
    key: &[u8],
    salt: Option<Vec<u8>>,
    iterations: u32,
    length: usize,
) -> Result<Py<PyBytes>> {
    let salt = salt.unwrap_or_else(|| vec![0u8; 0]);

    let key = utils::derive_key_pbkdf2(key, &salt, iterations, length);
    Ok(PyBytes::new(py, &key).into())
}

#[pyfunction]
#[pyo3(name = "derive_key_argon2")]
fn derive_key_argon2(py: Python, key: &[u8], parameters: &[u8]) -> Result<Py<PyBytes>> {
    let parameters = Argon2Parameters::try_from(parameters)?;

    let key = utils::derive_key_argon2(key, &parameters)?;
    Ok(PyBytes::new(py, &key).into())
}

#[pyfunction]
#[pyo3(name = "sign")]
#[pyo3(signature = (data, keypair, version=0))]
fn sign(py: Python, data: &[u8], keypair: &[u8], version: u16) -> Result<Py<PyBytes>> {
    let version = match SignatureVersion::try_from(version) {
        Ok(v) => v,
        Err(_) => {
            let error: DevolutionsCryptoError = Error::UnknownVersion.into();
            return Err(error);
        }
    };

    let keypair = SigningKeyPair::try_from(keypair)?;

    let signature: Vec<u8> = signature::sign(data, &keypair, version).into();
    Ok(PyBytes::new(py, &signature).into())
}

#[pyfunction]
#[pyo3(name = "verify_signature")]
fn verify_signature(
    py: Python,
    data: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Result<Py<PyBool>> {
    let public_key = SigningPublicKey::try_from(public_key)?;
    let signature = Signature::try_from(signature)?;

    Ok(PyBool::new(py, signature.verify(data, &public_key))
        .to_owned()
        .into())
}

#[pyfunction]
#[pyo3(name = "generate_keypair")]
#[pyo3(signature = (version=0))]
fn generate_keypair(py: Python, version: u16) -> Result<Keypair> {
    let version = match KeyVersion::try_from(version) {
        Ok(v) => v,
        Err(_) => {
            let error: DevolutionsCryptoError = Error::UnknownVersion.into();
            return Err(error);
        }
    };

    let kp = key::generate_keypair(version);

    let private_key: Vec<u8> = kp.private_key.into();
    let public_key: Vec<u8> = kp.public_key.into();

    let keypair = Keypair {
        private_key: PyBytes::new(py, &private_key).into(),
        public_key: PyBytes::new(py, &public_key).into(),
    };

    Ok(keypair)
}

#[pyfunction]
#[pyo3(name = "generate_signing_keypair")]
#[pyo3(signature = (version=0))]
fn generate_signing_keypair(py: Python, version: u16) -> Result<Py<PyBytes>> {
    let version = match SigningKeyVersion::try_from(version) {
        Ok(v) => v,
        Err(_) => {
            let error: DevolutionsCryptoError = Error::UnknownVersion.into();
            return Err(error);
        }
    };

    let kp = signing_key::generate_signing_keypair(version);

    let kp: Vec<u8> = kp.into();

    Ok(PyBytes::new(py, &kp).into())
}

#[pyfunction]
#[pyo3(name = "get_signing_public_key")]
fn get_signing_public_key(py: Python, keypair: &[u8]) -> Result<Py<PyBytes>> {
    let keypair = SigningKeyPair::try_from(keypair)?;

    let public_key: Vec<u8> = keypair.get_public_key().into();

    Ok(PyBytes::new(py, &public_key).into())
}

#[pymodule]
#[pyo3(name = "devolutions_crypto")]
fn devolutions_crypto_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_asymmetric, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_asymmetric, m)?)?;
    m.add_function(wrap_pyfunction!(hash_password, m)?)?;
    m.add_function(wrap_pyfunction!(verify_password, m)?)?;
    m.add_function(wrap_pyfunction!(derive_key_pbkdf2, m)?)?;
    m.add_function(wrap_pyfunction!(derive_key_argon2, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(generate_signing_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(get_signing_public_key, m)?)?;
    m.add_class::<Keypair>()?;
    m.add(
        "DevolutionsCryptoException",
        m.py().get_type::<DevolutionsCryptoException>(),
    )?;

    Ok(())
}

impl From<DevolutionsCryptoError> for PyErr {
    fn from(error: DevolutionsCryptoError) -> Self {
        match error {
            DevolutionsCryptoError::DevolutionsCrypto(error) => {
                let description: String = error.to_string();
                let name: &str = error.into();
                DevolutionsCryptoException::new_err((name, description))
            }
            DevolutionsCryptoError::Python(error) => error,
        }
    }
}

impl From<Error> for DevolutionsCryptoError {
    fn from(error: Error) -> Self {
        Self::DevolutionsCrypto(error)
    }
}

impl From<PyErr> for DevolutionsCryptoError {
    fn from(error: PyErr) -> Self {
        Self::Python(error)
    }
}
