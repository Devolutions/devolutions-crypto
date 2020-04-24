use num_enum::{IntoPrimitive, TryFromPrimitive};
use zeroize::Zeroize;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// The different data types.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum DataType {
    /// No data type. Only used as a default value.
    None = 0,
    /// A wrapped key.
    Key = 1,
    /// A wrapped ciphertext. Can be either symmetric or asymmetric.
    Ciphertext = 2,
    /// A wrapped password hash. Used to verify a password.
    PasswordHash = 3,
    /// A wrapped share. Used for secret sharing scheme.
    Share = 4,
}

impl Default for DataType {
    fn default() -> Self {
        Self::None
    }
}

/// The versions of the encryption scheme to use.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum CiphertextVersion {
    /// Uses the latest version.
    Latest = 0,
    /// Uses version 1: AES256-CBC-HMAC-SHA2-256.
    V1 = 1,
    /// Uses version 2: XChaCha20-Poly1305.
    V2 = 2,
}

impl Default for CiphertextVersion {
    fn default() -> Self {
        Self::Latest
    }
}

/// The versions of the password hashing scheme to use.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum PasswordHashVersion {
    /// Uses the latest version.
    Latest = 0,
    /// Uses version 1: PBKDF2-HMAC-SHA2-256.
    V1 = 1,
}

impl Default for PasswordHashVersion {
    fn default() -> Self {
        Self::Latest
    }
}

/// The versions of the key scheme to use.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum KeyVersion {
    /// Uses the latest version.
    Latest = 0,
    /// Uses version 1: Curve25519 keys and x25519 key exchange.
    V1 = 1,
}

impl Default for KeyVersion {
    fn default() -> Self {
        Self::Latest
    }
}

/// The versions of the secret sharing scheme to use.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(inspectable))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum SecretSharingVersion {
    /// Uses the latest version.
    Latest = 0,
    /// Uses version 1: Shamir Secret Sharing over GF256.
    V1 = 1,
}

impl Default for SecretSharingVersion {
    fn default() -> Self {
        Self::Latest
    }
}

#[derive(Clone, Copy, PartialEq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
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
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[repr(u16)]
pub enum ShareSubtype {
    None = 0,
}

impl Default for ShareSubtype {
    fn default() -> Self {
        Self::None
    }
}
