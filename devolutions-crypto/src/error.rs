//! Possible errors in the library.

use std;
use std::error::Error as _;
use std::fmt;
use std::io::Error;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

use block_modes::{BlockModeError, InvalidKeyIvLength};
use hmac::crypto_mac::InvalidKeyLength;
use hmac::crypto_mac::MacError;
use rand;

/// The enum containing the various error types.
#[derive(Debug)]
pub enum DevoCryptoError {
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
    /// A null pointer has been passed to the FFI interface. Error code: -31
    NullPointer,
    /// A cryptographic error occurred. Error code: -32
    CryptoError,
    /// An error with the Random Number Generator occurred. Error code: -33
    RandomError,
    /// A generic IO error has occurred. Error code: -34
    IoError(Error),
}

impl DevoCryptoError {
    /// Returns the error code associated with the error.
    /// This is useful for passing the exception type across a language boundary.
    pub fn error_code(&self) -> i64 {
        match *self {
            DevoCryptoError::InvalidLength => -1,
            DevoCryptoError::InvalidKeyLength => -2,
            DevoCryptoError::InvalidOutputLength => -3,
            DevoCryptoError::InvalidSignature => -11,
            DevoCryptoError::InvalidMac => -12,
            DevoCryptoError::InvalidDataType => -13,
            DevoCryptoError::UnknownType => -21,
            DevoCryptoError::UnknownSubtype => -22,
            DevoCryptoError::UnknownVersion => -23,
            DevoCryptoError::NullPointer => -31,
            DevoCryptoError::CryptoError => -32,
            DevoCryptoError::RandomError => -33,
            DevoCryptoError::IoError(_) => -34,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl DevoCryptoError {
    // Returns the error name for JavaScript error handling
    pub fn name(&self) -> &str {
        match *self {
            DevoCryptoError::InvalidLength => "InvalidLength",
            DevoCryptoError::InvalidKeyLength => "InvalidKeyLength",
            DevoCryptoError::InvalidOutputLength => "InvalidOutputLength",
            DevoCryptoError::InvalidSignature => "InvalidSignature",
            DevoCryptoError::InvalidMac => "InvalidMac",
            DevoCryptoError::InvalidDataType => "InvalidDataType",
            DevoCryptoError::UnknownType => "UnknownType",
            DevoCryptoError::UnknownSubtype => "UnknownSubtype",
            DevoCryptoError::UnknownVersion => "UnknownVersion",
            DevoCryptoError::NullPointer => "NullPointer",
            DevoCryptoError::CryptoError => "CryptoError",
            DevoCryptoError::RandomError => "RandomError",
            DevoCryptoError::IoError(_) => "IoError",
        }
    }
}

impl fmt::Display for DevoCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            DevoCryptoError::IoError(ref error) => error.fmt(f),
            _ => write!(f, "Error {}: {}", self.error_code(), self.description()),
        }
    }
}

impl std::error::Error for DevoCryptoError {
    fn description(&self) -> &str {
        match *self {
            DevoCryptoError::InvalidLength => "The provided data has an invalid length.",
            DevoCryptoError::InvalidKeyLength => "The key length is invalid.",
            DevoCryptoError::InvalidOutputLength => {
                "The length of the FFI output buffer is invalid."
            }
            DevoCryptoError::InvalidSignature => {
                "The signature of the data blob does not match 0x0d0c."
            }
            DevoCryptoError::InvalidMac => "The MAC is invalid.",
            DevoCryptoError::InvalidDataType => "The operation cannot be done with this type.",
            DevoCryptoError::UnknownType => "The data type is unknown.",
            DevoCryptoError::UnknownSubtype => "The data subtype is unknown.",
            DevoCryptoError::UnknownVersion => "The data type version is unknown.",
            DevoCryptoError::NullPointer => "A null pointer has been passed to the FFI interface.",
            DevoCryptoError::CryptoError => "A cryptographic error occurred.",
            DevoCryptoError::RandomError => "An error with the Random Number Generator occurred.",
            DevoCryptoError::IoError(ref error) => error.description(),
        }
    }
}

impl From<InvalidKeyLength> for DevoCryptoError {
    fn from(_error: InvalidKeyLength) -> DevoCryptoError {
        DevoCryptoError::InvalidKeyLength
    }
}

impl From<MacError> for DevoCryptoError {
    fn from(_error: MacError) -> DevoCryptoError {
        DevoCryptoError::InvalidMac
    }
}

impl From<InvalidKeyIvLength> for DevoCryptoError {
    fn from(_error: InvalidKeyIvLength) -> DevoCryptoError {
        DevoCryptoError::InvalidKeyLength
    }
}

impl From<BlockModeError> for DevoCryptoError {
    fn from(_error: BlockModeError) -> DevoCryptoError {
        DevoCryptoError::CryptoError
    }
}

impl From<aead::Error> for DevoCryptoError {
    fn from(_error: aead::Error) -> DevoCryptoError {
        DevoCryptoError::InvalidMac
    }
}

impl From<rand::Error> for DevoCryptoError {
    fn from(_error: rand::Error) -> DevoCryptoError {
        DevoCryptoError::RandomError
    }
}

impl From<std::io::Error> for DevoCryptoError {
    fn from(_error: std::io::Error) -> DevoCryptoError {
        DevoCryptoError::RandomError
    }
}

#[cfg(target_arch = "wasm32")]
impl From<DevoCryptoError> for JsValue {
    fn from(error: DevoCryptoError) -> JsValue {
        let js_error = js_sys::Error::new(error.description());

        js_error.set_name(error.name());
        js_error.into()
    }
}
