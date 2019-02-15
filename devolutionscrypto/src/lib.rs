#![feature(try_from)]

#[macro_use]
extern crate cfg_if;

extern crate aes;
extern crate block_modes;
extern crate byteorder;
extern crate hmac;
extern crate pbkdf2;
extern crate rand;
extern crate sha2;
extern crate x25519_dalek;

mod dc_data_blob;
mod dc_versions_impl;
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
use devocrypto_errors::DevoCryptoError;

use dc_data_blob::DcHeader;
use dc_versions_impl::hash_from_version;
use dc_versions_impl::HashImpl;
