use rand;

use block_modes::{BlockModeError, InvalidKeyIvLength};
use hmac::crypto_mac::InvalidKeyLength;
use hmac::crypto_mac::MacError;

use std;
use std::fmt;
use std::io::Error;

#[derive(Debug)]
pub enum DevoCryptoError {
    InvalidLength,
    InvalidKeyLength,
    InvalidSignature,
    InvalidMac,
    CryptoError,
    RandomError,
    IoError(Error),
}

impl fmt::Display for DevoCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            DevoCryptoError::InvalidLength => write!(f, "Cipher has an invalid length!"),
            DevoCryptoError::InvalidKeyLength => write!(f, "Key has an invalid length!"),
            DevoCryptoError::InvalidSignature => write!(f, "Cipher has an invalid signature!"),
            DevoCryptoError::InvalidMac => write!(f, "Cipher has an invalid MAC!"),
            DevoCryptoError::CryptoError => {
                write!(f, "An error happened during a cryptographic operation")
            }
            DevoCryptoError::RandomError => {
                write!(f, "An error happened while initializing the RNG")
            }
            DevoCryptoError::IoError(ref error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DevoCryptoError {
    fn description(&self) -> &str {
        match *self {
            DevoCryptoError::InvalidLength => "Cipher has an invalid length!",
            DevoCryptoError::InvalidKeyLength => "Key has an invalid length!",
            DevoCryptoError::InvalidSignature => "Cipher has an invalid signature!",
            DevoCryptoError::InvalidMac => "Cipher has an invalid MAC!",
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
