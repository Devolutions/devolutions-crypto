//! Possible errors in the library.

use std::fmt;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

use strum_macros::IntoStaticStr;

use block_modes::{BlockModeError, InvalidKeyIvLength};
use hmac::crypto_mac::InvalidKeyLength;
use hmac::crypto_mac::MacError;

/// This crate's error type.
#[derive(Debug, IntoStaticStr)]
pub enum Error {
    /// The provided data has an invalid length. Error code: -1
    InvalidLength,
    /// The key length is invalid. Error code: -2
    InvalidKeyLength,
    /// The length of the FFI output buffer is invalid. Error code: -3
    InvalidOutputLength,
    /// The signature of the data blob does not match 0x0d0c. Error code: -11
    InvalidSignature,
    /// The MAC is invalid. Error code: -12
    InvalidMac,
    /// The operation cannot be done with this type. Error code: -13
    InvalidDataType,
    /// The data type is unknown. Error code: -21
    UnknownType,
    /// The data subtype is unknown. Error code: -22
    UnknownSubtype,
    /// The data type version is unknown. Error code: -23
    UnknownVersion,
    /// The data is invalid. Error code: -24
    InvalidData,
    /// A null pointer has been passed to the FFI interface. Error code: -31
    NullPointer,
    /// A cryptographic error occurred. Error code: -32
    CryptoError,
    /// An error with the Random Number Generator occurred. Error code: -33
    RandomError,
    /// A generic IO error has occurred. Error code: -34
    IoError(std::io::Error),
    /// There is not enough shares to regenerate a secret: -41
    NotEnoughShares,
    /// The version of the multiple data is inconsistent: -42
    InconsistentVersion,
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
        }
    }

    /// Returns a description of the error
    pub fn description(&self) -> String {
        match *self {
            Error::InvalidLength => "The provided data has an invalid length.".to_string(),
            Error::InvalidKeyLength => "The key length is invalid.".to_string(),
            Error::InvalidOutputLength => {
                "The length of the FFI output buffer is invalid.".to_string()
            }
            Error::InvalidSignature => {
                "The signature of the data blob does not match 0x0d0c.".to_string()
            }
            Error::InvalidMac => "The MAC is invalid.".to_string(),
            Error::InvalidDataType => "The operation cannot be done with this type.".to_string(),
            Error::UnknownType => "The data type is unknown.".to_string(),
            Error::UnknownSubtype => "The data subtype is unknown.".to_string(),
            Error::InvalidData => "The data is invalid.".to_string(),
            Error::UnknownVersion => "The data type version is unknown.".to_string(),
            Error::NullPointer => {
                "A null pointer has been passed to the FFI interface.".to_string()
            }
            Error::CryptoError => "A cryptographic error occurred.".to_string(),
            Error::RandomError => "An error with the Random Number Generator occurred.".to_string(),
            Error::IoError(ref error) => error.to_string(),
            Error::NotEnoughShares => {
                "There wasn't enough share to regenerate the secret.".to_string()
            }
            Error::InconsistentVersion => {
                "The version is not the same for all the data.".to_string()
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::IoError(ref error) => error.fmt(f),
            _ => write!(f, "Error {}: {}", self.error_code(), self.description()),
        }
    }
}

impl From<InvalidKeyLength> for Error {
    fn from(_error: InvalidKeyLength) -> Error {
        Error::InvalidKeyLength
    }
}

impl From<MacError> for Error {
    fn from(_error: MacError) -> Error {
        Error::InvalidMac
    }
}

impl From<InvalidKeyIvLength> for Error {
    fn from(_error: InvalidKeyIvLength) -> Error {
        Error::InvalidKeyLength
    }
}

impl From<BlockModeError> for Error {
    fn from(_error: BlockModeError) -> Error {
        Error::CryptoError
    }
}

impl From<aead::Error> for Error {
    fn from(_error: aead::Error) -> Error {
        Error::InvalidMac
    }
}

impl From<rand::Error> for Error {
    fn from(_error: rand::Error) -> Error {
        Error::RandomError
    }
}

impl From<std::io::Error> for Error {
    fn from(_error: std::io::Error) -> Error {
        Error::RandomError
    }
}

impl From<argon2::Error> for Error {
    fn from(_error: argon2::Error) -> Self {
        Error::CryptoError
    }
}

#[cfg(target_arch = "wasm32")]
impl From<Error> for JsValue {
    fn from(error: Error) -> JsValue {
        let js_error = js_sys::Error::new(&error.description());

        js_error.set_name(error.into());
        js_error.into()
    }
}
