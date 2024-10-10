mod argon2parameters;
mod ciphertext;
mod key;
mod password_hash;
mod secret_sharing;
mod signature;
mod signing_key;
mod utils;

pub use argon2parameters::Argon2Parameters;
pub use argon2parameters::Argon2ParametersBuilder;
pub use ciphertext::*;
pub use key::*;
pub use password_hash::*;
pub use secret_sharing::*;
pub use signature::*;
pub use signing_key::*;
pub use utils::*;

pub use devolutions_crypto::Argon2Variant;
pub use devolutions_crypto::Argon2Version;
pub use devolutions_crypto::CiphertextVersion;
pub use devolutions_crypto::DataType;
pub use devolutions_crypto::Error as DevolutionsCryptoError;
pub use devolutions_crypto::KeyVersion;
pub use devolutions_crypto::PasswordHashVersion;
pub use devolutions_crypto::SecretSharingVersion;
pub use devolutions_crypto::SignatureVersion;
pub use devolutions_crypto::SigningKeyVersion;

pub use devolutions_crypto::Result;

uniffi::include_scaffolding!("devolutions_crypto");
