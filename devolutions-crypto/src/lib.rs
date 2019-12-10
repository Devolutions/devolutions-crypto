mod data_blob;
mod error;
pub mod utils;

use cfg_if::cfg_if;

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
