#[macro_use]
extern crate cfg_if;

mod dc_data_blob;

pub mod devocrypto;
mod devocrypto_errors;

pub type Result<T> = std::result::Result<T, devocrypto_errors::DevoCryptoError>;
use devocrypto_errors::DevoCryptoError;

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
