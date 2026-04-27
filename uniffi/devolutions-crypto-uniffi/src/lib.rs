mod argon2parameters;
mod ciphertext;
mod key;
mod password_hash;
mod secret_sharing;
mod signature;
mod signing_key;
mod utils;

pub use argon2parameters::*;
pub use ciphertext::*;
pub use key::*;
pub use password_hash::*;
pub use secret_sharing::*;
pub use signature::*;
pub use signing_key::*;
pub use utils::*;

pub use devolutions_crypto::{
    CiphertextVersion, DataType, Error as DevolutionsCryptoError, KeyVersion, PasswordHashVersion,
    Result, SecretSharingVersion, SignatureVersion, SigningKeyVersion,
};

#[uniffi::remote(Enum)]
pub enum DataType {
    None,
    Key,
    Ciphertext,
    PasswordHash,
    Share,
    SigningKey,
    Signature,
    OnlineCiphertext,
}

#[uniffi::remote(Enum)]
pub enum CiphertextVersion {
    Latest,
    V1,
    V2,
}

#[uniffi::remote(Enum)]
pub enum KeyVersion {
    Latest,
    V1,
}

#[uniffi::remote(Enum)]
pub enum PasswordHashVersion {
    Latest,
    V1,
}

#[uniffi::remote(Enum)]
pub enum SecretSharingVersion {
    Latest,
    V1,
}

#[uniffi::remote(Enum)]
pub enum SignatureVersion {
    Latest,
    V1,
}

#[uniffi::remote(Enum)]
pub enum SigningKeyVersion {
    Latest,
    V1,
}

#[uniffi::remote(Error)]
#[uniffi(flat_error)]
pub enum DevolutionsCryptoError {
    InvalidLength,
    InvalidKeyLength,
    InvalidOutputLength,
    InvalidSignature,
    InvalidMac,
    InvalidDataType,
    UnknownType,
    UnknownSubtype,
    UnknownVersion,
    InvalidData,
    NullPointer,
    CryptoError,
    RandomError,
    IoError,
    NotEnoughShares,
    InconsistentVersion,
    InvalidChunkLength,
    PoisonedMutex,
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Version {
    Version10,
    Version13,
}

impl From<Argon2Version> for argon2::Version {
    fn from(version: Argon2Version) -> Self {
        match version {
            Argon2Version::Version10 => argon2::Version::Version10,
            Argon2Version::Version13 => argon2::Version::Version13,
        }
    }
}

impl From<argon2::Version> for Argon2Version {
    fn from(version: argon2::Version) -> Self {
        match version {
            argon2::Version::Version10 => Argon2Version::Version10,
            argon2::Version::Version13 => Argon2Version::Version13,
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Variant {
    Argon2d,
    Argon2i,
    Argon2id,
}

impl From<Argon2Variant> for argon2::Variant {
    fn from(variant: Argon2Variant) -> Self {
        match variant {
            Argon2Variant::Argon2d => argon2::Variant::Argon2d,
            Argon2Variant::Argon2i => argon2::Variant::Argon2i,
            Argon2Variant::Argon2id => argon2::Variant::Argon2id,
        }
    }
}

impl From<argon2::Variant> for Argon2Variant {
    fn from(variant: argon2::Variant) -> Self {
        match variant {
            argon2::Variant::Argon2d => Argon2Variant::Argon2d,
            argon2::Variant::Argon2i => Argon2Variant::Argon2i,
            argon2::Variant::Argon2id => Argon2Variant::Argon2id,
        }
    }
}

uniffi::setup_scaffolding!();
