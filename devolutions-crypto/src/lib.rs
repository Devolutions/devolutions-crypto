#[macro_use]
extern crate cfg_if;

mod data_blob;
pub mod utils;

type Result<T> = std::result::Result<T, error::DevoCryptoError>;
mod error;

pub use data_blob::DcDataBlob;
pub use error::DevoCryptoError;

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        extern crate wasm_bindgen;
        pub mod wasm;
    }
    else {
        pub mod ffi;
    }
}
