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

// Re-export types from devolutions_crypto
pub use devolutions_crypto::CiphertextVersion;
pub use devolutions_crypto::DataType;
pub use devolutions_crypto::Error as DevolutionsCryptoError;
pub use devolutions_crypto::KeyVersion;
pub use devolutions_crypto::PasswordHashVersion;
pub use devolutions_crypto::SecretSharingVersion;
pub use devolutions_crypto::SignatureVersion;
pub use devolutions_crypto::SigningKeyVersion;

pub use devolutions_crypto::Result;

// Wrapper types for Argon2 enums from rust-argon2 crate
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
