mod argon2parameters;
mod enums;
mod error;
mod header;

pub mod ciphertext;
pub mod key;
pub mod password_hash;
pub mod secret_sharing;
pub mod utils;

use cfg_if::cfg_if;
use enums::{CiphertextSubtype, DataType, KeySubtype, PasswordHashSubtype, ShareSubtype};

pub use enums::{CiphertextVersion, KeyVersion, PasswordHashVersion, SecretSharingVersion};

pub use argon2parameters::Argon2Parameters;
pub use error::DevoCryptoError;
pub use header::Header;

type Result<T> = std::result::Result<T, error::DevoCryptoError>;

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        pub mod wasm;
    }
    else if #[cfg(feature = "ffi")] {
        pub mod ffi;
    }
}
