/// Primitives for Wayk Bastion Key derivation
pub mod key_derive;

/// Primitives for Wayk Bastion Key Exchange protocol
pub mod key_exchange;

/// Primitives for Field-Level Encryption (FLE)
pub mod fle;

use std::error::Error as StdError;
use std::fmt;
use uuid::Uuid;

/// Bastion crypto error
#[derive(Debug)]
pub enum Error {
    XChaCha20,
    InvalidSize { got: usize },
    Base64(base64::DecodeError),
    Rand(rand::Error),
    MasterKeyIdMismatch { expected: Uuid, found: Uuid },
    PadOperation,
    InvalidMagicNumber,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::XChaCha20 => write!(f, "XChaCha20 error"),
            Error::InvalidSize { got } => write!(f, "invalid size: got {}", got),
            Error::Base64(e) => write!(f, "base64 error: {}", e),
            Error::Rand(e) => write!(f, "rand error: {}", e),
            Error::MasterKeyIdMismatch { expected, found } => write!(
                f,
                "master key mismatch: expected {} but found {}",
                expected, found
            ),
            Error::PadOperation => write!(f, "pad operation failed"),
            Error::InvalidMagicNumber => write!(f, "invalid magic number"),
        }
    }
}

impl StdError for Error {}

impl From<rand::Error> for Error {
    fn from(e: rand::Error) -> Self {
        Self::Rand(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Self::Base64(e)
    }
}
