//! Possible errors in the library.
use cbc::cipher::block_padding::UnpadError;

#[cfg(feature = "wbindgen")]
use wasm_bindgen::JsValue;

use strum::IntoStaticStr;

use hmac::digest::MacError;

pub type Result<T> = std::result::Result<T, Error>;

// Doesn't work because Result is a type alias, keeping the commented code just in case we revisit someday
// impl<T, E> From<std::result::Result<T, E>> for Result<T>
// where E: Into<Error> {
//    fn from(value: std::result::Result<T, E>) -> Self {
//         match value {
//             Ok(t) => Ok(t),
//             Err(e) => Err(e.into()),
//         }
//     }
// }

/// This crate's error type.
#[derive(Debug, IntoStaticStr, thiserror::Error)]
pub enum Error {
    /// The provided data has an invalid length. Error code: -1
    #[error("The provided data has an invalid length")]
    InvalidLength,
    /// The key length is invalid. Error code: -2
    #[error("The key length is invalid.")]
    InvalidKeyLength,
    /// The length of the FFI output buffer is invalid. Error code: -3
    #[error("The length of the FFI output buffer is invalid.")]
    InvalidOutputLength,
    /// The signature of the data blob does not match 0x0d0c. Error code: -11
    #[error("The signature of the data blob does not match 0x0d0c.")]
    InvalidSignature,
    /// The MAC is invalid. Error code: -12
    #[error("The MAC is invalid.")]
    InvalidMac,
    /// The operation cannot be done with this type. Error code: -13
    #[error("The operation cannot be done with this type.")]
    InvalidDataType,
    /// The data type is unknown. Error code: -21
    #[error("The data type is unknown.")]
    UnknownType,
    /// The data subtype is unknown. Error code: -22
    #[error("The data subtype is unknown.")]
    UnknownSubtype,
    /// The data type version is unknown. Error code: -23
    #[error("The data type version is unknown.")]
    UnknownVersion,
    /// The data is invalid. Error code: -24
    #[error("The data is invalid.")]
    InvalidData,
    /// A null pointer has been passed to the FFI interface. Error code: -31
    #[error("A null pointer has been passed to the FFI interface.")]
    NullPointer,
    /// A cryptographic error occurred. Error code: -32
    #[error("A cryptographic error occurred.")]
    CryptoError,
    /// An error with the Random Number Generator occurred. Error code: -33
    #[error("An error with the Random Number Generator occurred.")]
    RandomError,
    /// A generic IO error has occurred. Error code: -34
    #[error("Generic IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// There is not enough shares to regenerate a secret: -41
    #[error("There wasn't enough share to regenerate the secret.")]
    NotEnoughShares,
    /// The version of the multiple data is inconsistent: -42
    #[error("The version is not the same for all the data.")]
    InconsistentVersion,
    /// The length of the data to encrypt/decrypt during online encryption is not the same as the chunk size: -43
    #[error("The length of the data to encrypt/decrypt during online encryption is not the same as the chunk size")]
    InvalidChunkLength,
    /// The mutex is poisoned and cannot be locked: -44
    #[error("The mutex is poisoned and cannot be locked")]
    PoisonedMutex,
}

impl Error {
    /// Returns the error code associated with the error.
    /// This is useful for passing the exception type across a language boundary.
    pub fn error_code(&self) -> i64 {
        match *self {
            Error::InvalidLength => -1,
            Error::InvalidKeyLength => -2,
            Error::InvalidOutputLength => -3,
            Error::InvalidSignature => -11,
            Error::InvalidMac => -12,
            Error::InvalidDataType => -13,
            Error::UnknownType => -21,
            Error::UnknownSubtype => -22,
            Error::UnknownVersion => -23,
            Error::InvalidData => -24,
            Error::NullPointer => -31,
            Error::CryptoError => -32,
            Error::RandomError => -33,
            Error::IoError(_) => -34,
            Error::NotEnoughShares => -41,
            Error::InconsistentVersion => -42,
            Error::InvalidChunkLength => -43,
            Error::PoisonedMutex => -44,
        }
    }
}

impl From<hmac::digest::InvalidLength> for Error {
    fn from(_error: hmac::digest::InvalidLength) -> Error {
        Error::InvalidKeyLength
    }
}

impl From<MacError> for Error {
    fn from(_error: MacError) -> Error {
        Error::InvalidMac
    }
}

impl From<UnpadError> for Error {
    fn from(_error: UnpadError) -> Error {
        Error::CryptoError
    }
}

impl From<aead::Error> for Error {
    fn from(_error: aead::Error) -> Error {
        Error::InvalidMac
    }
}

impl From<argon2::Error> for Error {
    fn from(_error: argon2::Error) -> Self {
        Error::CryptoError
    }
}

#[cfg(feature = "wbindgen")]
impl From<Error> for JsValue {
    fn from(error: Error) -> JsValue {
        let js_error = js_sys::Error::new(&error.to_string());

        js_error.set_name(error.into());
        js_error.into()
    }
}
