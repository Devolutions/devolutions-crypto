use num_enum::{IntoPrimitive, TryFromPrimitive};
use zeroize::Zeroize;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum DataType {
    None = 0,
    Key = 1,
    Ciphertext = 2,
    PasswordHash = 3,
    Share = 4,
}

impl Default for DataType {
    fn default() -> Self {
        Self::None
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum CiphertextVersion {
    Latest = 0,
    V1 = 1,
    V2 = 2,
}

impl Default for CiphertextVersion {
    fn default() -> Self {
        Self::Latest
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum PasswordHashVersion {
    Latest = 0,
    V1 = 1,
}

impl Default for PasswordHashVersion {
    fn default() -> Self {
        Self::Latest
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum KeyVersion {
    Latest = 0,
    V1 = 1,
}

impl Default for KeyVersion {
    fn default() -> Self {
        Self::Latest
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum SecretSharingVersion {
    Latest = 0,
    V1 = 1,
}

impl Default for SecretSharingVersion {
    fn default() -> Self {
        Self::Latest
    }
}

#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum CiphertextSubtype {
    None = 0,
    Symmetric = 1,
    Asymmetric = 2,
}

impl Default for CiphertextSubtype {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum KeySubtype {
    None = 0,
    Private = 1,
    Public = 2,
}

impl Default for KeySubtype {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum PasswordHashSubtype {
    None = 0,
}

impl Default for PasswordHashSubtype {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum ShareSubtype {
    None = 0,
}

impl Default for ShareSubtype {
    fn default() -> Self {
        Self::None
    }
}
