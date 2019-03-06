#[macro_use]
extern crate cfg_if;

mod dc_data_blob;
pub mod devocrypto;

mod devocrypto_errors;

pub type Result<T> = std::result::Result<T, devocrypto_errors::DevoCryptoError>;

pub use devocrypto_errors::DevoCryptoError;
pub use dc_data_blob::DcDataBlob;

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        extern crate wasm_bindgen;
        pub mod wasm;
    }
    else {
        extern crate libc;
        pub mod ffi;
    }
}
