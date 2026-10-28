use num_enum::{IntoPrimitive, TryFromPrimitive};
use zeroize::Zeroize;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[cfg(feature = "wbindgen")]
use wasm_bindgen::prelude::*;

/// The different data types.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
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
    /// A wrapped online ciphertext that can be encrypted/decrypted chunk by chunk
    OnlineCiphertext = 7,
    /// Serialized key derivation parameters.
    KeyDerivation = 8,
    /// A wrapped payload combining key derivation parameters and ciphertext.
    KdfEncryptedData = 9,
}

/// The versions of the encryption scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
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
    /// Uses version 3 (FIPS): AES-256-GCM with an HKDF-SHA256 derived key and P-256 ECDH for asymmetric.
    #[cfg(feature = "fips")]
    V3 = 3,
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
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum PasswordHashVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: PBKDF2-HMAC-SHA2-256.
    V1 = 1,
    /// Uses version 2: Argon2id.
    V2 = 2,
    /// Uses version 3 (FIPS): PBKDF2-HMAC-SHA256.
    #[cfg(feature = "fips")]
    V3 = 3,
}

/// The versions of the key scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum KeyVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: Curve25519 keys and x25519 key exchange.
    V1 = 1,
    /// Uses version 3 (FIPS): NIST P-256 keys and ECDH key exchange.
    #[cfg(feature = "fips")]
    V3 = 3,
}

#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum SigningKeyVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: Ed25519.
    V1 = 1,
    /// Uses version 3 (FIPS): ECDSA over NIST P-256 with SHA-256.
    #[cfg(feature = "fips")]
    V3 = 3,
}

/// The versions of the secret sharing scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
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
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum SignatureVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: ed25519
    V1 = 1,
    /// Uses version 3 (FIPS): ECDSA over NIST P-256 with SHA-256.
    #[cfg(feature = "fips")]
    V3 = 3,
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
    Secret = 4,
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

/// The versions of the key derivation scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum KeyDerivationVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1: PBKDF2-HMAC-SHA256.
    V1 = 1,
    /// Uses version 2: Argon2id.
    V2 = 2,
    /// Uses version 3 (FIPS): PBKDF2-HMAC-SHA256.
    #[cfg(feature = "fips")]
    V3 = 3,
}

/// The versions of the KDF-encrypt scheme to use.
#[cfg_attr(feature = "wbindgen", wasm_bindgen())]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum KdfEncryptedDataVersion {
    /// Uses the latest version.
    #[default]
    Latest = 0,
    /// Uses version 1.
    V1 = 1,
}

#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[repr(u16)]
#[derive(Default)]
pub enum KeyDerivationSubtype {
    #[default]
    None = 0,
}

#[derive(Clone, Copy, PartialEq, Eq, Zeroize, IntoPrimitive, TryFromPrimitive, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[repr(u16)]
#[derive(Default)]
pub enum KdfEncryptedDataSubtype {
    #[default]
    None = 0,
}

/// Version policy, the only place where the `fips` feature changes which versions are produced.
///
/// * `resolve_latest` maps `Latest` to the version produced by this build
///   (`$default`, or `$fips` with the `fips` feature) and keeps explicit versions.
/// * `resolve_approved` also rejects, with the `fips` feature, every version but `$fips`.
///   It is used by the functions producing encrypted data, password hashes, derived keys and shares.
///
/// Types without a FIPS version (`=> none`) cannot produce new data with the `fips` feature.
macro_rules! version_policy {
    ($($ty:ident: $default:ident => none),+ $(,)?) => {$(
        impl $ty {
            /// Returns the concrete version that `Latest` stands for, or `self`
            /// if it is already a concrete version.
            pub fn resolve_latest(self) -> Self {
                match self {
                    Self::Latest => Self::$default,
                    version => version,
                }
            }

            pub(crate) fn resolve_approved(self) -> crate::Result<Self> {
                #[cfg(feature = "fips")]
                return Err(crate::Error::NotFipsApproved);
                #[cfg(not(feature = "fips"))]
                Ok(self.resolve_latest())
            }
        }
    )+};
    ($($ty:ident: $default:ident => $fips:ident),+ $(,)?) => {$(
        impl $ty {
            /// Returns the concrete version that `Latest` stands for in this build, or `self`
            /// if it is already a concrete version.
            pub fn resolve_latest(self) -> Self {
                match self {
                    #[cfg(not(feature = "fips"))]
                    Self::Latest => Self::$default,
                    #[cfg(feature = "fips")]
                    Self::Latest => Self::$fips,
                    version => version,
                }
            }

            #[allow(dead_code)]
            pub(crate) fn resolve_approved(self) -> crate::Result<Self> {
                match self.resolve_latest() {
                    #[cfg(feature = "fips")]
                    Self::$fips => Ok(Self::$fips),
                    #[cfg(feature = "fips")]
                    _ => Err(crate::Error::NotFipsApproved),
                    #[cfg(not(feature = "fips"))]
                    version => Ok(version),
                }
            }
        }
    )+};
}

version_policy! {
    CiphertextVersion: V2 => V3,
    PasswordHashVersion: V2 => V3,
    KeyVersion: V1 => V3,
    SigningKeyVersion: V1 => V3,
    SignatureVersion: V1 => V3,
    KeyDerivationVersion: V2 => V3,
}

version_policy! {
    OnlineCiphertextVersion: V1 => none,
    SecretSharingVersion: V1 => none,
}
