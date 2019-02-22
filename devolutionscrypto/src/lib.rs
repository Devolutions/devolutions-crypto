#![feature(try_from)]

#[macro_use]
extern crate cfg_if;

//mod dc_data_blob;
//mod dc_versions_impl;

pub mod devocrypto;
mod devocrypto_errors;

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

pub type Result<T> = std::result::Result<T, devocrypto_errors::DevoCryptoError>;
//use devocrypto_errors::DevoCryptoError;

//use dc_data_blob::DcHeader;
//use dc_versions_impl::hash_from_version;
//use dc_versions_impl::HashImpl;
