use num_enum::{IntoPrimitive, TryFromPrimitive};
use zeroize::Zeroize;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[cfg(feature = "wbindgen")]
use wasm_bindgen::prelude::*;

/// The different data types.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[cfg_attr(feature = "uniffi-support", derive(uniffi::Enum))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum DataType {
    /// No data type. Only used as a default value.
    #[default]
    None = 0,
    /// A wrapped key.
    Key = 1,
    /// A wrapped ciphertext. Can be either symmetric or asymmetric.
    Ciphertext = 2,
    /// A wrapped password hash. Used to verify a password.
    PasswordHash = 3,
    /// A wrapped share. Used for secret sharing scheme.
    Share = 4,
    /// A wrapped key used to sign data.
    SigningKey = 5,
    /// A wrapped signature.
    Signature = 6,
    /// A wrapped online ciphertextr that can be encrypted/decrypted chunk by chunk
    OnlineCiphertext = 7,
}

/// The versions of the encryption scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[cfg_attr(feature = "uniffi-support", derive(uniffi::Enum))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum CiphertextVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: AES256-CBC-HMAC-SHA2-256.
    V1 = 1,
    /// Uses version 2: XChaCha20-Poly1305.
    V2 = 2,
}

/// The versions of the online encryption scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum OnlineCiphertextVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: XChaCha20-Poly1305 wrapped in a STREAM construction.
    V1 = 1,
}

/// The versions of the password hashing scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[cfg_attr(feature = "uniffi-support", derive(uniffi::Enum))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum PasswordHashVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: PBKDF2-HMAC-SHA2-256.
    V1 = 1,
}

/// The versions of the key scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[cfg_attr(feature = "uniffi-support", derive(uniffi::Enum))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum KeyVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: Curve25519 keys and x25519 key exchange.
    V1 = 1,
}

#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[cfg_attr(feature = "uniffi-support", derive(uniffi::Enum))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum SigningKeyVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: Ed25519.
    V1 = 1,
}

/// The versions of the secret sharing scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[cfg_attr(feature = "uniffi-support", derive(uniffi::Enum))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum SecretSharingVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: Shamir Secret Sharing over GF256.
    V1 = 1,
}

/// The versions of the secret sharing scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[cfg_attr(feature = "uniffi-support", derive(uniffi::Enum))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum SignatureVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: ed25519
    V1 = 1,
}

#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[repr(u16)]
#[derive(Default)]
pub enum CiphertextSubtype {
    #[default]
    None = 0,
    Symmetric = 1,
    Asymmetric = 2,
}

#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[repr(u16)]
#[derive(Default)]
pub enum KeySubtype {
    #[default]
    None = 0,
    Private = 1,
    Public = 2,
    Pair = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[repr(u16)]
#[derive(Default)]
pub enum PasswordHashSubtype {
    #[default]
    None = 0,
}

#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[repr(u16)]
#[derive(Default)]
pub enum ShareSubtype {
    #[default]
    None = 0,
}

#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[repr(u16)]
#[derive(Default)]
pub enum SignatureSubtype {
    #[default]
    None = 0,
}
