mod argon2parameters;
mod data_blob;
mod enums;
mod error;
pub mod utils;

use cfg_if::cfg_if;
use enums::DataType;

pub use argon2parameters::Argon2Parameters;
pub use data_blob::DcDataBlob;
pub use error::DevoCryptoError;

type Result<T> = std::result::Result<T, error::DevoCryptoError>;

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        pub mod wasm;
    }
    else {
        pub mod ffi;
    }
}
