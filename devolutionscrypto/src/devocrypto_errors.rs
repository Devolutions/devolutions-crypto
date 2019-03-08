//! Possible errors in the library.

use rand;

use block_modes::{BlockModeError, InvalidKeyIvLength};
use hmac::crypto_mac::InvalidKeyLength;
use hmac::crypto_mac::MacError;

use std;
use std::error::Error as _;
use std::fmt;
use std::io::Error;

/// The enum containing the various error types.
#[derive(Debug)]
pub enum DevoCryptoError {
    /// The provided data has an invalid length.
    InvalidLength,
    InvalidKeyLength,
    InvalidOutputLength,
    InvalidSignature,
    InvalidMac,
    InvalidDataType,
    UnknownType,
    UnknownSubtype,
    UnknownVersion,
    NullPointer,
    CryptoError,
    RandomError,
    IoError(Error),
}

impl DevoCryptoError {
    /// Returns the error code associated with the error.
    /// This is useful for passing the exception type across a language boundary.
    pub fn error_code(&self) -> i64 {
        match *self {
            DevoCryptoError::InvalidLength => -1,
            DevoCryptoError::InvalidKeyLength => -2,
            DevoCryptoError::InvalidOutputLength => -13,
            DevoCryptoError::InvalidSignature => -3,
            DevoCryptoError::InvalidMac => -4,
            DevoCryptoError::InvalidDataType => -8,
            DevoCryptoError::UnknownType => -9,
            DevoCryptoError::UnknownSubtype => -10,
            DevoCryptoError::UnknownVersion => -11,
            DevoCryptoError::NullPointer => -12,
            DevoCryptoError::CryptoError => -5,
            DevoCryptoError::RandomError => -6,
            DevoCryptoError::IoError(_) => -7,
        }
    }
}

impl fmt::Display for DevoCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            DevoCryptoError::InvalidLength => write!(f, "{}", self.description()),
            DevoCryptoError::InvalidKeyLength => write!(f, "{}", self.description()),
            DevoCryptoError::InvalidOutputLength => write!(f, "{}", self.description()),
            DevoCryptoError::InvalidSignature => write!(f, "{}", self.description()),
            DevoCryptoError::InvalidMac => write!(f, "{}", self.description()),
            DevoCryptoError::InvalidDataType => write!(f, "{}", self.description()),
            DevoCryptoError::UnknownType => write!(f, "{}", self.description()),
            DevoCryptoError::UnknownSubtype => write!(f, "{}", self.description()),
            DevoCryptoError::UnknownVersion => write!(f, "{}", self.description()),
            DevoCryptoError::NullPointer => write!(f, "{}", self.description()),
            DevoCryptoError::CryptoError => write!(f, "{}", self.description()),
            DevoCryptoError::RandomError => write!(f, "{}", self.description()),
            DevoCryptoError::IoError(ref error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DevoCryptoError {
    fn description(&self) -> &str {
        match *self {
            DevoCryptoError::InvalidLength => "The data blob has an invalid length!",
            DevoCryptoError::InvalidKeyLength => "Key has an invalid length!",
            DevoCryptoError::InvalidOutputLength => "The output buffer size is invalid!",
            DevoCryptoError::InvalidSignature => "Cipher has an invalid signature!",
            DevoCryptoError::InvalidMac => "Cipher has an invalid MAC!",
            DevoCryptoError::InvalidDataType => "Operation cannot be done with this data type!",
            DevoCryptoError::UnknownType => "The type specified in the header is unknown",
            DevoCryptoError::UnknownSubtype => "The subtype specified in the header is unknown",
            DevoCryptoError::UnknownVersion => "The version specified in the header is unknown",
            DevoCryptoError::NullPointer => "A null pointer has been passed to the library",
            DevoCryptoError::CryptoError => "An error happened during a cryptographic operation",
            DevoCryptoError::RandomError => "An error happened while initializing the RNG",
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
