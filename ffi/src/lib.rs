#![allow(non_snake_case)]

//! FFI interface for use with other languages. Mostly used for C and C#.
//! # Safety
//! Note that this API is unsafe by nature: Rust can do a couple of check but cannot garantee
//!     the received pointers are valid. It is the job of the calling language to verify it passes
//!     the right pointers and length.
//! The Size functions must be called to get the required length of the returned array before
//!     calling it.

use devolutions_crypto::online_ciphertext::OnlineCiphertextDecryptor;
use devolutions_crypto::online_ciphertext::OnlineCiphertextEncryptor;
use devolutions_crypto::online_ciphertext::OnlineCiphertextHeader;
use devolutions_crypto::utils;
use devolutions_crypto::Argon2Parameters;
use devolutions_crypto::DataType;
use devolutions_crypto::Error;

use base64::{engine::general_purpose, Engine as _};

use devolutions_crypto::ciphertext::{
    encrypt_asymmetric_with_aad, encrypt_with_aad, Ciphertext, CiphertextVersion,
};
use devolutions_crypto::key::{
    generate_keypair, mix_key_exchange, KeyVersion, PrivateKey, PublicKey,
};
use devolutions_crypto::password_hash::{hash_password, PasswordHash, PasswordHashVersion};
use devolutions_crypto::secret_sharing::{
    generate_shared_key, join_shares, SecretSharingVersion, Share,
};
use devolutions_crypto::OnlineCiphertextVersion;
use devolutions_crypto::{
    signature,
    signature::{Signature, SignatureVersion},
};

use devolutions_crypto::{
    signing_key,
    signing_key::{SigningKeyPair, SigningKeyVersion, SigningPublicKey},
};

use devolutions_crypto::Result;

use std::borrow::Borrow;
use std::ffi::c_void;
use std::slice;
use std::sync::Mutex;

use zeroize::Zeroizing;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Encrypt a data blob
/// # Arguments
///  * `data` - Pointer to the data to encrypt.
///  * `data_length` - Length of the data to encrypt.
///  * `key` - Pointer to the key to use to encrypt.
///  * `key_length` - Length of the key to use to encrypt.
///  * `aad` - Pointer to additionnal data to authenticate alongside the ciphertext.
///             Pass null if there is not additionnal data to authenticate.
///  * `aad_length` - Length of the additionnal data to authenticate. Pass 0 if there is no data.
///  * `result` - Pointer to the buffer to write the ciphertext to.
///  * `result_length` - Length of the buffer to write the ciphertext to. You can get the value by
///                         calling EncryptSize() beforehand.
///  * `version` - Version to use. Use 0 for the latest one.
/// # Returns
/// This returns the length of the ciphertext. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn Encrypt(
    data: *const u8,
    data_length: usize,
    key: *const u8,
    key_length: usize,
    aad: *const u8,
    aad_length: usize,
    result: *mut u8,
    result_length: usize,
    version: u16,
) -> i64 {
    if data.is_null() || key.is_null() || result.is_null() {
        return Error::NullPointer.error_code();
    };

    if result_length != EncryptSize(data_length, version) as usize {
        return Error::InvalidOutputLength.error_code();
    }

    let aad = if aad.is_null() {
        &[]
    } else {
        slice::from_raw_parts(aad, aad_length)
    };

    let data = slice::from_raw_parts(data, data_length);
    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    let version = match CiphertextVersion::try_from(version) {
        Ok(v) => v,
        Err(_) => return Error::UnknownVersion.error_code(),
    };

    match encrypt_with_aad(data, key, aad, version) {
        Ok(res) => {
            let res: Zeroizing<Vec<u8>> = Zeroizing::new(res.into());
            let length = res.len();
            result[0..length].copy_from_slice(&res);
            length as i64
        }
        Err(e) => e.error_code(),
    }
}

/// Encrypt a data blob
/// # Arguments
///  * `data` - Pointer to the data to encrypt.
///  * `data_length` - Length of the data to encrypt.
///  * `public_key` - Pointer to the public key to use to encrypt.
///  * `public_key_length` - Length of the public key to use to encrypt.
///  * `aad` - Pointer to additionnal data to authenticate alongside the ciphertext.
///             Pass null if there is not additionnal data to authenticate.
///  * `aad_length` - Length of the additionnal data to authenticate. Pass 0 if there is no data.
///  * `result` - Pointer to the buffer to write the ciphertext to.
///  * `result_length` - Length of the buffer to write the ciphertext to. You can get the value by
///                         calling EncryptAsymmetricSize() beforehand.
///  * `version` - Version to use. Use 0 for the latest one.
/// # Returns
/// This returns the length of the asymmetric ciphertext. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn EncryptAsymmetric(
    data: *const u8,
    data_length: usize,
    public_key: *const u8,
    public_key_length: usize,
    aad: *const u8,
    aad_length: usize,
    result: *mut u8,
    result_length: usize,
    version: u16,
) -> i64 {
    if data.is_null() || public_key.is_null() || result.is_null() {
        return Error::NullPointer.error_code();
    };

    if result_length != EncryptAsymmetricSize(data_length, version) as usize {
        return Error::InvalidOutputLength.error_code();
    }

    let aad = if aad.is_null() {
        &[]
    } else {
        slice::from_raw_parts(aad, aad_length)
    };

    let data = slice::from_raw_parts(data, data_length);
    let public_key = PublicKey::try_from(slice::from_raw_parts(public_key, public_key_length));

    match public_key {
        Ok(public_key) => {
            let result = slice::from_raw_parts_mut(result, result_length);

            let version = match CiphertextVersion::try_from(version) {
                Ok(v) => v,
                Err(_) => return Error::UnknownVersion.error_code(),
            };

            match encrypt_asymmetric_with_aad(data, &public_key, aad, version) {
                Ok(res) => {
                    let res: Zeroizing<Vec<u8>> = Zeroizing::new(res.into());
                    let length = res.len();

                    result[0..length].copy_from_slice(&res);
                    length as i64
                }
                Err(e) => e.error_code(),
            }
        }
        Err(e) => e.error_code(),
    }
}

/// Get the size of the resulting ciphertext.
/// # Arguments
///  * data_length - Length of the plaintext.
/// # Returns
/// Returns the length of the ciphertext to input as `result_length` in `Encrypt()`.
#[no_mangle]
pub extern "C" fn EncryptSize(data_length: usize, version: u16) -> i64 {
    match version {
        1 => {
            (8 + 16 + (data_length / 16 + 1) * 16 + 32) as i64 // Header + IV + data(padded to 16) + HMAC
        }
        0 | 2 => {
            (8 + 24 + data_length + 16) as i64 // Header + nonce + data + Poly1305 tag
        }
        _ => Error::UnknownVersion.error_code(),
    }
}

/// Get the size of the resulting asymmetric ciphertext.
/// # Arguments
///  * data_length - Length of the plaintext.
/// # Returns
/// Returns the length of the asymmetric ciphertext to input as `result_length` in `EncryptAsymmetric()`.
#[no_mangle]
pub extern "C" fn EncryptAsymmetricSize(data_length: usize, version: u16) -> i64 {
    match version {
        0 | 2 => {
            (8 + 32 + 24 + data_length + 16) as i64 // Header + public_key + nonce + data + Poly1305 tag
        }
        _ => Error::UnknownVersion.error_code(),
    }
}

/// Decrypt a data blob
/// # Arguments
///  * `data` - Pointer to the data to decrypt.
///  * `data_length` - Length of the data to decrypt.
///  * `key` - Pointer to the key to use to decrypt.
///  * `key_length` - Length of the key to use to decrypt.
///  * `aad` - Pointer to additionnal data to authenticate alongside the ciphertext.
///             Pass null if there is not additionnal data to authenticate.
///  * `aad_length` - Length of the additionnal data to authenticate. Pass 0 if there is no data.
///  * `result` - Pointer to the buffer to write the plaintext to.
///  * `result_length` - Length of the buffer to write the plaintext to.
///                     The safest size is the same size as the ciphertext.
/// # Returns
/// This returns the length of the plaintext. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn Decrypt(
    data: *const u8,
    data_length: usize,
    key: *const u8,
    key_length: usize,
    aad: *const u8,
    aad_length: usize,
    result: *mut u8,
    result_length: usize,
) -> i64 {
    if data.is_null() || key.is_null() || result.is_null() {
        return Error::NullPointer.error_code();
    };

    let aad = if aad.is_null() {
        &[]
    } else {
        slice::from_raw_parts(aad, aad_length)
    };

    let data = slice::from_raw_parts(data, data_length);
    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    match Ciphertext::try_from(data) {
        Ok(res) => match res.decrypt_with_aad(key, aad) {
            Ok(res) => {
                let res = Zeroizing::new(res);

                if result.len() >= res.len() {
                    let length = res.len();
                    result[0..length].copy_from_slice(&res);
                    length as i64
                } else {
                    Error::InvalidOutputLength.error_code()
                }
            }
            Err(e) => e.error_code(),
        },
        Err(e) => e.error_code(),
    }
}

/// Decrypt a data blob
/// # Arguments
///  * `data` - Pointer to the data to decrypt.
///  * `data_length` - Length of the data to decrypt.
///  * `private_key` - Pointer to the private key to use to decrypt.
///  * `private_key_length` - Length of the private key to use to decrypt.
///  * `aad` - Pointer to additionnal data to authenticate alongside the ciphertext.
///             Pass null if there is not additionnal data to authenticate.
///  * `aad_length` - Length of the additionnal data to authenticate. Pass 0 if there is no data.
///  * `result` - Pointer to the buffer to write the plaintext to.
///  * `result_length` - Length of the buffer to write the plaintext to.
///                     The safest size is the same size as the ciphertext.
/// # Returns
/// This returns the length of the plaintext. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn DecryptAsymmetric(
    data: *const u8,
    data_length: usize,
    private_key: *const u8,
    private_key_length: usize,
    aad: *const u8,
    aad_length: usize,
    result: *mut u8,
    result_length: usize,
) -> i64 {
    if data.is_null() || private_key.is_null() || result.is_null() {
        return Error::NullPointer.error_code();
    };

    let aad = if aad.is_null() {
        &[]
    } else {
        slice::from_raw_parts(aad, aad_length)
    };

    let data = slice::from_raw_parts(data, data_length);
    let private_key = PrivateKey::try_from(slice::from_raw_parts(private_key, private_key_length));

    match private_key {
        Ok(private_key) => {
            let result = slice::from_raw_parts_mut(result, result_length);

            match Ciphertext::try_from(data) {
                Ok(res) => match res.decrypt_asymmetric_with_aad(&private_key, aad) {
                    Ok(res) => {
                        let res = Zeroizing::new(res);
                        if result.len() >= res.len() {
                            let length = res.len();
                            result[0..length].copy_from_slice(&res);
                            length as i64
                        } else {
                            Error::InvalidOutputLength.error_code()
                        }
                    }
                    Err(e) => e.error_code(),
                },
                Err(e) => e.error_code(),
            }
        }
        Err(e) => e.error_code(),
    }
}

/// Sign data using a keypair to certify its authenticity.
/// # Arguments
///  * `data` - Pointer to the data to sign.
///  * `data_length` - Length of the data to sign.
///  * `keypair` - pointer to the keypair to use to sign the data.
///  * `keypair_length` - Length of the keypair to use to sign the data.
///  * `result` - Pointer to the buffer to write the signature to.
///  * `result_length` - Length of the buffer to write the signature to. You can get the value by
///                         calling SignSize() beforehand.
/// # Returns
/// This returns 0 if the operation worked. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn Sign(
    data: *const u8,
    data_length: usize,
    keypair: *const u8,
    keypair_length: usize,
    result: *mut u8,
    result_length: usize,
    version: u16,
) -> i64 {
    if data.is_null() || keypair.is_null() || result.is_null() {
        return Error::NullPointer.error_code();
    };

    if result_length != SignSize(version) as usize {
        return Error::InvalidOutputLength.error_code();
    };

    let data = slice::from_raw_parts(data, data_length);
    let keypair = slice::from_raw_parts(keypair, keypair_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    match SigningKeyPair::try_from(keypair) {
        Ok(keypair) => {
            let version = match SignatureVersion::try_from(version) {
                Ok(v) => v,
                Err(_) => return Error::UnknownVersion.error_code(),
            };

            let signature: Vec<u8> = signature::sign(data, &keypair, version).into();

            result[0..signature.len()].copy_from_slice(&signature);

            0
        }
        Err(e) => e.error_code(),
    }
}

/// Verify some data using a signature and the corresponding public key.
/// # Arguments
///  * `data` - Pointer to the data to verify.
///  * `data_length` - Length of the data to verify.
///  * `public_key` - Pointer to the public part of the keypair that was used to sign the data.
///  * `public_key` - Length of the public part of the keypair that was used to sign the data.
///  * `signature` - Pointer to the signature to verify.
///  * `signature_length` - Length of the signature to verify.
/// # Returns
/// Returns 0 if the data, the signature or the public key is invalid or 1 if everything is valid. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn VerifySignature(
    data: *const u8,
    data_length: usize,
    public_key: *const u8,
    public_key_length: usize,
    signature: *const u8,
    signature_length: usize,
) -> i64 {
    if data.is_null() || public_key.is_null() || signature.is_null() {
        return Error::NullPointer.error_code();
    };

    let data = slice::from_raw_parts(data, data_length);
    let public_key = slice::from_raw_parts(public_key, public_key_length);
    let signature = slice::from_raw_parts(signature, signature_length);

    match SigningPublicKey::try_from(public_key) {
        Ok(public_key) => match Signature::try_from(signature) {
            Ok(signature) => {
                if signature.verify(data, &public_key) {
                    1
                } else {
                    0
                }
            }
            Err(e) => e.error_code(),
        },
        Err(e) => e.error_code(),
    }
}

/// Get the size of the resulting signature.
/// # Returns
/// Returns the length of the signature to input as `result_length` in `Sign()`.
#[no_mangle]
pub extern "C" fn SignSize(_version: u16) -> i64 {
    8 + 64 // header + signature
}

/// Hash a password using a high-cost algorithm.
/// # Arguments
///  * `password` - Pointer to the password to hash.
///  * `password_length` - Length of the password to hash.
///  * `iterations` - Number of iterations of the password hash.
///                   A higher number is slower but harder to brute-force. The recommended is 10000,
///                   but the number can be set by the user.
///  * `result` - Pointer to the buffer to write the hash to.
///  * `result_length` - Length of the buffer to write the hash to. You can get the value by
///                         calling HashPasswordLength() beforehand.
/// # Returns
/// This returns the length of the hash. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn HashPassword(
    password: *const u8,
    password_length: usize,
    iterations: u32,
    result: *mut u8,
    result_length: usize,
) -> i64 {
    if password.is_null() || result.is_null() {
        return Error::NullPointer.error_code();
    };

    if result_length != HashPasswordLength() as usize {
        return Error::InvalidOutputLength.error_code();
    };

    let password = slice::from_raw_parts(password, password_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    let res: Zeroizing<Vec<u8>> =
        match hash_password(password, iterations, PasswordHashVersion::Latest) {
            Ok(x) => Zeroizing::new(x.into()),
            Err(e) => return e.error_code(),
        };

    let length = res.len();
    result[0..length].copy_from_slice(&res);
    length as i64
}

/// Get the size of the resulting hash.
/// # Returns
/// Returns the length of the hash to input as `result_length` in `HashPassword()`.
#[no_mangle]
pub extern "C" fn HashPasswordLength() -> i64 {
    8 + 4 + 32 + 32 // Header + iterations + salt + hash
}

/// Verify a password against a hash with constant-time equality.
/// # Arguments
///  * `password` - Pointer to the password to verify.
///  * `password_length` - Length of the password to verify.
///  * `hash` - Pointer to the hash to verify.
///  * `hash_length` - Length of the hash to verify.
/// # Returns
/// Returns 0 if the password is invalid or 1 if the password is valid. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn VerifyPassword(
    password: *const u8,
    password_length: usize,
    hash: *const u8,
    hash_length: usize,
) -> i64 {
    if password.is_null() || hash.is_null() {
        return Error::NullPointer.error_code();
    };

    let password = slice::from_raw_parts(password, password_length);
    let hash = slice::from_raw_parts(hash, hash_length);

    match PasswordHash::try_from(hash) {
        Ok(res) => {
            if res.verify_password(password) {
                1
            } else {
                0
            }
        }
        Err(e) => e.error_code(),
    }
}

/// Generate a key pair to perform a key exchange. Must be used with MixKey()
/// # Arguments
///  * `private` - Pointer to the buffer to write the private key to.
///  * `private_length` - Length of the buffer to write the private key to.
///                         You can get the value by calling `GenerateKeyPairSize()` beforehand.
///  * `public` - Pointer to the buffer to write the public key to.
///  * `public_length` - Length of the buffer to write the public key to.
///                         You can get the value by calling `GenerateKeyPairSize()` beforehand.
/// # Returns
/// Returns 0 if the generation worked. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn GenerateKeyPair(
    private: *mut u8,
    private_length: usize,
    public: *mut u8,
    public_length: usize,
) -> i64 {
    if private.is_null() || public.is_null() {
        return Error::NullPointer.error_code();
    };

    if private_length != GenerateKeyPairSize() as usize
        || public_length != GenerateKeyPairSize() as usize
    {
        return Error::InvalidOutputLength.error_code();
    }

    let private = slice::from_raw_parts_mut(private, private_length);
    let public = slice::from_raw_parts_mut(public, public_length);

    let keypair = generate_keypair(KeyVersion::Latest);

    let priv_res: Zeroizing<Vec<u8>> = Zeroizing::new(keypair.private_key.into());
    let pub_res: Zeroizing<Vec<u8>> = Zeroizing::new(keypair.public_key.into());

    public[0..pub_res.len()].copy_from_slice(&pub_res);
    private[0..priv_res.len()].copy_from_slice(&priv_res);
    0
}

/// Generate a key pair to sign and verify data with.
/// # Arguments
///  * `keypair` - Pointer to the buffer to write the keypair to.
///  * `keypair_length` - Length of the buffer to write the keypair to.
///                         You can get the value by calling `GenerateSigningKeyPairSize()` beforehand.
///  * `version` - Version to use. Use 0 for the latest one.
/// # Returns
/// Returns 0 if the generation worked. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn GenerateSigningKeyPair(
    keypair: *mut u8,
    keypair_length: usize,
    version: u16,
) -> i64 {
    if keypair.is_null() {
        return Error::NullPointer.error_code();
    };

    if keypair_length != GenerateSigningKeyPairSize(version) as usize {
        return Error::InvalidOutputLength.error_code();
    }

    let keypair = slice::from_raw_parts_mut(keypair, keypair_length);

    let version = match SigningKeyVersion::try_from(version) {
        Ok(v) => v,
        Err(_) => return Error::UnknownVersion.error_code(),
    };

    let generated_keypair = signing_key::generate_signing_keypair(version);

    let keypair_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(generated_keypair.into());

    keypair[0..keypair_bytes.len()].copy_from_slice(&keypair_bytes);

    0
}

/// Get the public part of a keypair used to sign data.
/// # Arguments
///  * `keypair` - Pointer to the buffer containing the keypair.
///  * `keypair_length` - Length of the buffer containing the keypair.
///  * `public` - Pointer to the buffer to write the public key to.
///  * `public_length` - Length of the buffer to write the public key to.
///                         You can get the value by calling `GetSigningPublicKeySize()` beforehand.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn GetSigningPublicKey(
    keypair: *const u8,
    keypair_length: usize,
    public: *mut u8,
    public_length: usize,
) -> i64 {
    if keypair.is_null() || public.is_null() {
        return Error::NullPointer.error_code();
    };

    if public_length != GetSigningPublicKeySize(keypair, keypair_length) as usize {
        return Error::InvalidOutputLength.error_code();
    };

    let keypair = slice::from_raw_parts(keypair, keypair_length);
    let public = slice::from_raw_parts_mut(public, public_length);

    let keypair = SigningKeyPair::try_from(keypair);
    match keypair {
        Ok(keypair) => {
            let public_key: Vec<u8> = keypair.get_public_key().into();
            public[..public_key.len()].copy_from_slice(&public_key);

            0
        }
        Err(e) => e.error_code(),
    }
}

/// Get the size of the keys in the key exchange key pair.
/// # Returns
/// Returns the length of the keys to input as `private_length`
///     and `public_length` in `GenerateKeyPair()`.
#[no_mangle]
pub extern "C" fn GenerateKeyPairSize() -> i64 {
    8 + 32 // header + key length
}

/// Get the size of the keypair used for signing.
/// # Returns
/// Returns the length of the keypair to input as `keypair_length`
///   in `GenerateSigningKeyPair()`.
#[no_mangle]
pub extern "C" fn GenerateSigningKeyPairSize(_version: u16) -> i64 {
    8 + 64 // header + keypair length
}

/// Get the size of the public key used for signing.
/// # Returns
/// Returns the length of the public key to input as `public_length`
///   in `GetSigningPublicKey()`.
#[no_mangle]
pub extern "C" fn GetSigningPublicKeySize(_keypair: *const u8, _keypair_length: usize) -> i64 {
    8 + 32 // header + public key length
}

/// Performs a key exchange.
/// # Arguments
///  * `private` - Pointer to the buffer containing the private key.
///  * `private_length` - Length of the buffer containing the private key.
///  * `public` - Pointer to the buffer containing the public key.
///  * `public_length` - Length of the buffer containing the public key.
///  * `shared` - Pointer to the buffer to write the resulting shared key.
///  * `shared_size` - Length of the buffer containing the shared key.
/// # Returns
/// Returns 0 if the key exchange worked. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn MixKeyExchange(
    private: *const u8,
    private_size: usize,
    public: *const u8,
    public_size: usize,
    shared: *mut u8,
    shared_size: usize,
) -> i64 {
    if private.is_null() || public.is_null() || shared.is_null() {
        return Error::NullPointer.error_code();
    };

    if shared_size != MixKeyExchangeSize() as usize {
        return Error::InvalidOutputLength.error_code();
    }

    let public = slice::from_raw_parts(public, public_size);
    let private = slice::from_raw_parts(private, private_size);
    let shared = slice::from_raw_parts_mut(shared, shared_size);

    match (PrivateKey::try_from(private), PublicKey::try_from(public)) {
        (Ok(private), Ok(public)) => match mix_key_exchange(&private, &public) {
            Ok(res) => {
                let res = Zeroizing::new(res);
                shared[0..res.len()].copy_from_slice(&res);
                0
            }
            Err(e) => e.error_code(),
        },
        (Ok(_), Err(e)) => e.error_code(),
        (Err(e), Ok(_)) => e.error_code(),
        (Err(e), Err(_)) => e.error_code(),
    }
}

/// Get the size of the keys in the key exchange key pair.
/// # Returns
/// Returns the length of the keys to input as `shared_length` in `MixKeyExchange()`.
#[no_mangle]
pub extern "C" fn MixKeyExchangeSize() -> i64 {
    32
}

/// Generates a secret key shared amongst multiple actor.
/// # Arguments
///  * n_shares - The number of shares to generate.
///  * threshold - The number of shares required to regenerate the secret.
///  * length - The length of the generated secret
///  * shares - The output buffers. This is a 2-dimensionnal array representing the shares.
/// # Returns
/// Returns 0 if the operation is successful. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn GenerateSharedKey(
    n_shares: u8,
    threshold: u8,
    length: usize,
    shares: *const *mut u8,
) -> i64 {
    if shares.is_null() {
        return Error::NullPointer.error_code();
    };

    match generate_shared_key(n_shares, threshold, length, SecretSharingVersion::Latest) {
        Ok(s) => {
            let shares = slice::from_raw_parts(shares, n_shares as usize);

            for (s, res_s) in s.into_iter().zip(shares) {
                if res_s.is_null() {
                    return Error::NullPointer.error_code();
                };

                let s: Vec<u8> = s.into();
                let res_s =
                    slice::from_raw_parts_mut(*res_s, GenerateSharedKeySize(length) as usize);
                res_s.copy_from_slice(&s);
            }
            0
        }
        Err(e) => e.error_code(),
    }
}

/// The size, in bytes, of each resulting shares
/// # Arguments
///  * secret_length - The length of the desired secret
/// # Returns
/// Returns the size, in bytes, of each resulting shares.
#[no_mangle]
pub extern "C" fn GenerateSharedKeySize(secret_length: usize) -> i64 {
    (secret_length + 10) as i64
}

/// Join multiple shares to regenerate a shared secret.
/// # Arguments
///  * n_shares - The number of shares sent to the method
///  * share_length - The length of each share
///  * shares - The shares to join
///  * secret - The output buffer to write the shared secret to.
///  * secret_length - The length of the output buffer. Get the value with JoinSharesSize.
/// # Returns
/// Returns 0 if the operation is successful. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn JoinShares(
    n_shares: usize,
    share_length: usize,
    shares: *const *const u8,
    secret: *mut u8,
    secret_length: usize,
) -> i64 {
    if shares.is_null() || secret.is_null() {
        return Error::NullPointer.error_code();
    };

    if secret_length != JoinSharesSize(share_length) as usize {
        return Error::InvalidOutputLength.error_code();
    }

    let shares: Result<Vec<Share>> = slice::from_raw_parts(shares, n_shares)
        .iter()
        .map(|s| Share::try_from(slice::from_raw_parts(*s, share_length)))
        .collect();

    match shares {
        Ok(shares) => match join_shares(&shares) {
            Ok(s) => {
                let secret = slice::from_raw_parts_mut(secret, secret_length);
                secret.copy_from_slice(&s);
                0
            }
            Err(e) => e.error_code(),
        },
        Err(e) => e.error_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn NewOnlineEncryptor(
    key: *const u8,
    key_size: usize,
    aad: *const u8,
    aad_size: usize,
    chunk_size: u32,
    asymmetric: bool,
    version: u16,
    output: *mut *mut c_void,
) -> i64 {
    if key.is_null() || aad.is_null() {
        return Error::NullPointer.error_code();
    };

    let key = slice::from_raw_parts(key, key_size);
    let aad = slice::from_raw_parts(aad, aad_size);

    let version = match OnlineCiphertextVersion::try_from(version) {
        Ok(v) => v,
        Err(_) => return Error::UnknownVersion.error_code(),
    };

    let encryptor = if asymmetric {
        let public_key = match PublicKey::try_from(key) {
            Ok(pk) => pk,
            Err(e) => return e.error_code(),
        };

        OnlineCiphertextEncryptor::new_asymmetric(&public_key, aad, chunk_size, version)
    } else {
        OnlineCiphertextEncryptor::new(key, aad, chunk_size, version)
    };

    let encryptor = Box::new(Mutex::new(encryptor));

    *output = Box::into_raw(encryptor) as *mut c_void;

    0
}

#[no_mangle]
pub unsafe extern "C" fn NewOnlineDecryptor(
    key: *const u8,
    key_size: usize,
    aad: *const u8,
    aad_size: usize,
    header: *const u8,
    header_size: usize,
    asymmetric: bool,
    output: *mut *mut c_void,
) -> i64 {
    if key.is_null() | aad.is_null() | header.is_null() {
        return Error::NullPointer.error_code();
    };

    let key = slice::from_raw_parts(key, key_size);
    let aad = slice::from_raw_parts(aad, aad_size);
    let header = slice::from_raw_parts(header, header_size);

    let header = match OnlineCiphertextHeader::try_from(header) {
        Ok(h) => h,
        Err(e) => return e.error_code(),
    };

    let decryptor = if asymmetric {
        let private_key = match PrivateKey::try_from(key) {
            Ok(pk) => pk,
            Err(e) => return e.error_code(),
        };

        header.into_decryptor_asymmetric(&private_key, aad)
    } else {
        header.into_decryptor(key, aad)
    };

    let decryptor = match decryptor {
        Ok(d) => d,
        Err(e) => return e.error_code(),
    };

    let decryptor = Box::new(Mutex::new(decryptor));

    *output = Box::into_raw(decryptor) as *mut c_void;

    0
}

#[no_mangle]
pub unsafe extern "C" fn OnlineEncryptorGetHeader(
    ptr: *const c_void,
    result: *mut u8,
    result_size: usize,
) -> i64 {
    if ptr.is_null() | result.is_null() {
        return Error::NullPointer.error_code();
    };

    let encryptor = &*(ptr as *const Mutex<OnlineCiphertextEncryptor>);
    let header: Vec<u8> = match encryptor.lock() {
        Ok(c) => c.get_header().borrow().into(),
        Err(_) => return Error::PoisonedMutex.error_code(),
    };

    if header.len() != result_size {
        return Error::InvalidOutputLength.error_code();
    }

    result.copy_from(header.as_slice().as_ptr() as *const u8, result_size);

    result_size as i64
}

#[no_mangle]
pub unsafe extern "C" fn OnlineDecryptorGetHeader(
    ptr: *const c_void,
    result: *mut u8,
    result_size: usize,
) -> i64 {
    if ptr.is_null() | result.is_null() {
        return Error::NullPointer.error_code();
    };

    let decryptor = &*(ptr as *const Mutex<OnlineCiphertextDecryptor>);
    let header: Vec<u8> = match decryptor.lock() {
        Ok(c) => c.get_header().borrow().into(),
        Err(_) => return Error::PoisonedMutex.error_code(),
    };

    if header.len() != result_size {
        return Error::InvalidOutputLength.error_code();
    }

    result.copy_from(header.as_slice().as_ptr() as *const u8, result_size);

    result_size as i64
}

#[no_mangle]
pub unsafe extern "C" fn OnlineEncryptorNextChunk(
    ptr: *mut c_void,
    data: *const u8,
    data_size: usize,
    aad: *const u8,
    aad_size: usize,
    result: *mut u8,
    result_size: usize,
) -> i64 {
    if ptr.is_null() | aad.is_null() | data.is_null() | result.is_null() {
        return Error::NullPointer.error_code();
    };

    let encryptor = &mut *(ptr as *mut Mutex<OnlineCiphertextEncryptor>);
    let mut encryptor = match encryptor.lock() {
        Ok(c) => c,
        Err(_) => return Error::PoisonedMutex.error_code(),
    };

    let data = slice::from_raw_parts(data, data_size);
    let aad = slice::from_raw_parts(aad, aad_size);

    let encrypted = match encryptor.encrypt_next_chunk(data, aad) {
        Ok(e) => e,
        Err(e) => return e.error_code(),
    };

    if encrypted.len() != result_size {
        return Error::InvalidOutputLength.error_code();
    }

    result.copy_from(encrypted.as_slice().as_ptr() as *const u8, result_size);

    result_size as i64
}

#[no_mangle]
pub unsafe extern "C" fn OnlineDecryptorNextChunk(
    ptr: *mut c_void,
    data: *const u8,
    data_size: usize,
    aad: *const u8,
    aad_size: usize,
    result: *mut u8,
    result_size: usize,
) -> i64 {
    if ptr.is_null() | aad.is_null() | data.is_null() | result.is_null() {
        return Error::NullPointer.error_code();
    };

    let decryptor = &mut *(ptr as *mut Mutex<OnlineCiphertextDecryptor>);
    let mut decryptor = match decryptor.lock() {
        Ok(c) => c,
        Err(_) => return Error::PoisonedMutex.error_code(),
    };

    let data = slice::from_raw_parts(data, data_size);
    let aad = slice::from_raw_parts(aad, aad_size);

    let decrypted = match decryptor.decrypt_next_chunk(data, aad) {
        Ok(e) => e,
        Err(e) => return e.error_code(),
    };

    if decrypted.len() != result_size {
        return Error::InvalidOutputLength.error_code();
    }

    result.copy_from(decrypted.as_slice().as_ptr() as *const u8, result_size);

    result_size as i64
}

#[no_mangle]
pub unsafe extern "C" fn OnlineEncryptorLastChunk(
    ptr: *mut c_void,
    data: *const u8,
    data_size: usize,
    aad: *const u8,
    aad_size: usize,
    result: *mut u8,
    result_size: usize,
) -> i64 {
    if ptr.is_null() | aad.is_null() | data.is_null() | result.is_null() {
        return Error::NullPointer.error_code();
    };

    let encryptor = Box::from_raw(ptr as *mut Mutex<OnlineCiphertextEncryptor>);

    let encryptor = match encryptor.into_inner() {
        Ok(c) => c,
        Err(_) => return Error::PoisonedMutex.error_code(),
    };

    let data = slice::from_raw_parts(data, data_size);
    let aad = slice::from_raw_parts(aad, aad_size);

    let encrypted = match encryptor.encrypt_last_chunk(data, aad) {
        Ok(e) => e,
        Err(e) => return e.error_code(),
    };

    if result_size < encrypted.len() {
        return Error::InvalidOutputLength.error_code();
    }

    result.copy_from(encrypted.as_slice().as_ptr() as *const u8, encrypted.len());

    encrypted.len() as i64
}

#[no_mangle]
pub unsafe extern "C" fn OnlineDecryptorLastChunk(
    ptr: *mut c_void,
    data: *const u8,
    data_size: usize,
    aad: *const u8,
    aad_size: usize,
    result: *mut u8,
    result_size: usize,
) -> i64 {
    if ptr.is_null() | aad.is_null() | data.is_null() | result.is_null() {
        return Error::NullPointer.error_code();
    };

    let decryptor = Box::from_raw(ptr as *mut Mutex<OnlineCiphertextDecryptor>);
    let decryptor = match decryptor.into_inner() {
        Ok(c) => c,
        Err(_) => return Error::PoisonedMutex.error_code(),
    };

    let data = slice::from_raw_parts(data, data_size);
    let aad = slice::from_raw_parts(aad, aad_size);

    let decrypted = match decryptor.decrypt_last_chunk(data, aad) {
        Ok(e) => e,
        Err(e) => return e.error_code(),
    };

    if result_size < decrypted.len() {
        return Error::InvalidOutputLength.error_code();
    }

    result.copy_from(decrypted.as_slice().as_ptr() as *const u8, decrypted.len());

    decrypted.len() as i64
}

#[no_mangle]
pub unsafe extern "C" fn OnlineEncryptorGetHeaderSize(ptr: *const c_void) -> i64 {
    if ptr.is_null() {
        return Error::NullPointer.error_code();
    };

    let encryptor = &*(ptr as *const Mutex<OnlineCiphertextEncryptor>);
    let header = match encryptor.lock() {
        Ok(c) => c.get_header(),
        Err(_) => return Error::PoisonedMutex.error_code(),
    };

    header.get_serialized_size() as i64
}

#[no_mangle]
pub unsafe extern "C" fn OnlineDecryptorGetHeaderSize(ptr: *const c_void) -> i64 {
    if ptr.is_null() {
        return Error::NullPointer.error_code();
    };

    let decryptor = &*(ptr as *const Mutex<OnlineCiphertextDecryptor>);
    let header = match decryptor.lock() {
        Ok(c) => c.get_header(),
        Err(_) => return Error::PoisonedMutex.error_code(),
    };

    header.get_serialized_size() as i64
}

#[no_mangle]
pub unsafe extern "C" fn OnlineEncryptorGetChunkSize(ptr: *const c_void) -> i64 {
    if ptr.is_null() {
        return Error::NullPointer.error_code();
    };

    let encryptor = &*(ptr as *const Mutex<OnlineCiphertextEncryptor>);
    match encryptor.lock() {
        Ok(c) => c.get_chunk_size() as i64,
        Err(_) => Error::PoisonedMutex.error_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OnlineDecryptorGetChunkSize(ptr: *const c_void) -> i64 {
    if ptr.is_null() {
        return Error::NullPointer.error_code();
    };

    let decryptor = &*(ptr as *const Mutex<OnlineCiphertextDecryptor>);
    match decryptor.lock() {
        Ok(c) => c.get_chunk_size() as i64,
        Err(_) => Error::PoisonedMutex.error_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OnlineEncryptorGetTagSize(ptr: *const c_void) -> i64 {
    if ptr.is_null() {
        return Error::NullPointer.error_code();
    };

    let encryptor = &*(ptr as *const Mutex<OnlineCiphertextEncryptor>);
    match encryptor.lock() {
        Ok(c) => c.get_tag_size() as i64,
        Err(_) => Error::PoisonedMutex.error_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OnlineDecryptorGetTagSize(ptr: *const c_void) -> i64 {
    if ptr.is_null() {
        return Error::NullPointer.error_code();
    };

    let decryptor = &*(ptr as *const Mutex<OnlineCiphertextDecryptor>);
    match decryptor.lock() {
        Ok(c) => c.get_tag_size() as i64,
        Err(_) => Error::PoisonedMutex.error_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn FreeOnlineEncryptor(ptr: *mut c_void) -> i64 {
    if ptr.is_null() {
        return Error::NullPointer.error_code();
    };

    drop(Box::from_raw(ptr as *mut Mutex<OnlineCiphertextEncryptor>));

    0
}

#[no_mangle]
pub unsafe extern "C" fn FreeOnlineDecryptor(ptr: *mut c_void) -> i64 {
    if ptr.is_null() {
        return Error::NullPointer.error_code();
    };

    drop(Box::from_raw(ptr as *mut Mutex<OnlineCiphertextDecryptor>));

    0
}

/// The size, in bytes, of the resulting secret
/// # Arguments
///  * share_length - The length of a share
/// # Returns
/// Returns the size, in bytes, of each resulting secret.
#[no_mangle]
pub extern "C" fn JoinSharesSize(share_length: usize) -> i64 {
    (share_length - 10) as i64
}

/// Generate a key using a CSPRNG.
/// # Arguments
///  * key - Pointer to the buffer to fill with random values.
///  * key_length - Length of the buffer to fill.
/// # Returns
/// Returns 0 if the operation is successful. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn GenerateKey(key: *mut u8, key_length: usize) -> i64 {
    if key.is_null() {
        return Error::NullPointer.error_code();
    };

    let key = slice::from_raw_parts_mut(key, key_length);

    let k = match utils::generate_key(key_length) {
        Ok(x) => Zeroizing::new(x),
        Err(e) => return e.error_code(),
    };

    key.copy_from_slice(&k);
    0
}

/// Derive a key with Argon2 to create a new one. Can be used with a password.
/// # Arguments
///  * key - Pointer to the key to derive.
///  * key_length - Length of the key to derive.
///  * argon2_parameters - Pointer to the buffer containing the argon2 parameters.
///  * argon2_parameters_length - Length of the argon2 parameters to use.
///  * result - Pointer to the buffer to write the new key to.
///  * result_length - Length of buffer to write the key to.
/// # Returns
/// Returns 0 if the operation is successful. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn DeriveKeyArgon2(
    key: *const u8,
    key_length: usize,
    argon2_parameters: *const u8,
    argon2_parameters_length: usize,
    result: *mut u8,
    result_length: usize,
) -> i64 {
    if key.is_null() || result.is_null() || argon2_parameters.is_null() {
        return Error::NullPointer.error_code();
    };

    let key = slice::from_raw_parts(key, key_length);

    let argon2_parameters_raw = slice::from_raw_parts(argon2_parameters, argon2_parameters_length);

    let argon2_parameters = match Argon2Parameters::try_from(argon2_parameters_raw) {
        Ok(x) => x,
        Err(e) => return e.error_code(),
    };

    let native_result = match utils::derive_key_argon2(key, &argon2_parameters) {
        Ok(x) => Zeroizing::new(x),
        Err(e) => return e.error_code(),
    };

    let result = slice::from_raw_parts_mut(result, result_length);

    result.copy_from_slice(&native_result);
    0
}

/// Derive a key with PBKDF2 to create a new one. Can be used with a password.
/// # Arguments
///  * key - Pointer to the key to derive.
///  * key_length - Length of the key to derive.
///  * salt - Pointer to the buffer containing the salt. Can be null.
///  * salt_length - Length of the salt to use.
///  * result - Pointer to the buffer to write the new key to.
///  * result_length - Length of buffer to write the key to.
/// # Returns
/// Returns 0 if the operation is successful. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn DeriveKeyPbkdf2(
    key: *const u8,
    key_length: usize,
    salt: *const u8,
    salt_length: usize,
    niterations: u32,
    result: *mut u8,
    result_length: usize,
) -> i64 {
    if key.is_null() || result.is_null() {
        return Error::NullPointer.error_code();
    };

    let salt = if salt.is_null() || salt_length == 0 {
        b""
    } else {
        slice::from_raw_parts(salt, salt_length)
    };

    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    let native_result = Zeroizing::new(utils::derive_key_pbkdf2(
        key,
        salt,
        niterations,
        result_length,
    ));
    result.copy_from_slice(&native_result);
    0
}

/// Validate if the header of the data is valid and consistant.
/// # Arguments
///  * `data` - Pointer to the input buffer.
///  * `data_length` - Length of the input buffer.
///  * `data_type` - Type of the data.
/// # Returns
/// 1 if the header is valid, 0 if it's not, and a negative value if there is an error.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn ValidateHeader(
    data: *const u8,
    data_length: usize,
    data_type: u16,
) -> i64 {
    if data.is_null() {
        return Error::NullPointer.error_code();
    };

    let data = slice::from_raw_parts(data, data_length);

    match DataType::try_from(data_type) {
        Ok(t) => {
            if utils::validate_header(data, t) {
                1
            } else {
                0
            }
        }
        Err(_) => Error::UnknownType.error_code(),
    }
}

/// This is binded here for one specific use case, do not use it if you don't know what you're doing.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn ScryptSimple(
    password: *const u8,
    password_length: usize,
    salt: *const u8,
    salt_length: usize,
    log_n: u8,
    r: u32,
    p: u32,
    output: *mut u8,
    output_length: usize,
) -> i64 {
    if password.is_null() && salt.is_null() && output.is_null() {
        return Error::NullPointer.error_code();
    };

    let password = slice::from_raw_parts(password, password_length);
    let salt = slice::from_raw_parts(salt, salt_length);

    let hash = utils::scrypt_simple(password, salt, log_n, r, p);

    let output = slice::from_raw_parts_mut(output, output_length);
    output[..hash.len()].copy_from_slice(hash.as_bytes());
    hash.len() as i64
}

/// This is binded here for one specific use case, do not use it if you don't know what you're doing.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn ScryptSimpleSize() -> i64 {
    256
}

/// Get the default Argon2Parameters struct values.
/// # Arguments
///  * argon2_parameters - Pointer to the output buffer.
///  * argon2_parameters_length - Length of the output buffer.
/// # Returns
/// Returns 0 if the operation is successful.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn GetDefaultArgon2Parameters(
    argon2_parameters: *mut u8,
    argon2_parameters_length: usize,
) -> i64 {
    let argon2_parameters = slice::from_raw_parts_mut(argon2_parameters, argon2_parameters_length);

    let argon2_parameters_raw: Vec<u8> = (&Argon2Parameters::default()).into();
    argon2_parameters.copy_from_slice(&argon2_parameters_raw);
    0
}

/// Size of the Argon2Parameters struct.
/// # Returns
/// Returns 0 if the operation is successful.
#[no_mangle]
pub extern "C" fn GetDefaultArgon2ParametersSize() -> i64 {
    // Length is calculated this way:
    // 5 * u32 + 2 * u8(enums) + 2 * u32(lengths) + 2 * vec.len();
    // In case of default parameters AssociatedData is of length 0 and Salt length is 16.
    46
}

///  Size, in bits, of the key used for the current Encrypt() implementation.
/// # Returns
/// Returns the size, in bits, of the key used fot the current Encrypt() implementation.
#[no_mangle]
pub extern "C" fn KeySize() -> u32 {
    256
}

/// Decode a base64 string to bytes.
/// # Arguments
///  * input - Pointer to the string to decode.
///  * input_length - Length of the string to decode.
///  * output - Pointer to the output buffer.
///  * output_length - Length of the output buffer.
/// # Returns
/// Returns the size of the decoded string.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn Decode(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
) -> i64 {
    if input.is_null() || output.is_null() {
        return Error::NullPointer.error_code();
    };

    let input = std::str::from_utf8_unchecked(slice::from_raw_parts(input, input_length));
    let output = slice::from_raw_parts_mut(output, output_length);

    match devolutions_crypto::utils::base64_decode(input) {
        Ok(res) => {
            output.copy_from_slice(&res);
            res.len() as i64
        }
        Err(_err) => -1,
    }
}

/// Encode a byte array to a base64 string.
/// # Arguments
///  * input - Pointer to the buffer to encode.
///  * input_length - Length of the buffer to encode.
///  * output - Pointer to the output buffer.
///  * output_length - Length of the output buffer.
/// # Returns
/// Returns the size, in bytes, of the output buffer.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn Encode(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
) -> i64 {
    if input.is_null() || output.is_null() {
        return Error::NullPointer.error_code();
    };

    let input = slice::from_raw_parts(input, input_length);
    let output = slice::from_raw_parts_mut(output, output_length);

    let encode_res = devolutions_crypto::utils::base64_encode(input).into_bytes();

    output.copy_from_slice(&encode_res);

    encode_res.len() as i64
}

/// Decode a base64 string to bytes using base64url.
/// # Arguments
///  * input - Pointer to the string to decode.
///  * input_length - Length of the string to decode.
///  * output - Pointer to the output buffer.
///  * output_length - Length of the output buffer.
/// # Returns
/// Returns the size of the decoded string.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn DecodeUrl(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
) -> i64 {
    if input.is_null() || output.is_null() {
        return Error::NullPointer.error_code();
    };

    let input = std::str::from_utf8_unchecked(slice::from_raw_parts(input, input_length));
    let output = slice::from_raw_parts_mut(output, output_length);

    match general_purpose::URL_SAFE_NO_PAD.decode_slice_unchecked(input, output) {
        Ok(res) => res as i64,
        Err(_e) => -1,
    }
}

/// Encode a byte array to a base64 string using base64url.
/// # Arguments
///  * input - Pointer to the buffer to encode.
///  * input_length - Length of the buffer to encode.
///  * output - Pointer to the output buffer.
///  * output_length - Length of the output buffer.
/// # Returns
/// Returns the size, in bytes, of the output buffer.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn EncodeUrl(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
) -> i64 {
    if input.is_null() || output.is_null() {
        return Error::NullPointer.error_code();
    };

    let input = slice::from_raw_parts(input, input_length);
    let output = slice::from_raw_parts_mut(output, output_length);

    match general_purpose::URL_SAFE_NO_PAD.encode_slice(input, output) {
        Ok(res) => res as i64,
        Err(_err) => -1,
    }
}

/// Compare two byte arrays with constant-time equality.
/// # Arguments
///  * `x` - Pointer to the first value to compare.
///  * `x_length` - Length of the first value to compare.
///  * `y` - Pointer to the second value to compare.
///  * `y_length` - Length of the second value to compare.
/// # Returns
/// Returns 0 if the values are not equal is invalid or 1 if the values are equal. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn ConstantTimeEquals(
    x: *const u8,
    x_length: usize,
    y: *const u8,
    y_length: usize,
) -> i64 {
    if x.is_null() || y.is_null() {
        return Error::NullPointer.error_code();
    };

    let x = slice::from_raw_parts(x, x_length);
    let y = slice::from_raw_parts(y, y_length);

    if utils::constant_time_equals(x, y) {
        1
    } else {
        0
    }
}

///  Size of the version string
/// # Returns
/// Returns the size of the version string
#[no_mangle]
pub extern "C" fn VersionSize() -> i64 {
    VERSION.len() as i64
}

///  Fill the output buffer with the version string
/// # Arguments
///  * output - Pointer to the output buffer.
///  * output_length - Length of the output buffer.
/// # Returns
/// Returns the size, in bytes, of the output buffer.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
#[no_mangle]
pub unsafe extern "C" fn Version(output: *mut u8, output_length: usize) -> i64 {
    if output.is_null() {
        return Error::NullPointer.error_code();
    };

    let output = slice::from_raw_parts_mut(output, output_length);
    output.copy_from_slice(VERSION.as_bytes());

    output.len() as i64
}

#[test]
fn test_encrypt_length() {
    let key = b"supersecret";
    let length_zero = b"";
    let length_one_block = b"hello";
    let one_full_block = b"0123456789abcdef";
    let multiple_blocks = b"0123456789abcdefghijkl";

    let length_zero_enc: Vec<u8> =
        devolutions_crypto::ciphertext::encrypt(length_zero, key, CiphertextVersion::Latest)
            .unwrap()
            .into();
    let length_one_block_enc: Vec<u8> =
        devolutions_crypto::ciphertext::encrypt(length_one_block, key, CiphertextVersion::Latest)
            .unwrap()
            .into();
    let one_full_block_enc: Vec<u8> =
        devolutions_crypto::ciphertext::encrypt(one_full_block, key, CiphertextVersion::Latest)
            .unwrap()
            .into();
    let multiple_blocks_enc: Vec<u8> =
        devolutions_crypto::ciphertext::encrypt(multiple_blocks, key, CiphertextVersion::Latest)
            .unwrap()
            .into();

    assert_eq!(
        length_zero_enc.len() as i64,
        EncryptSize(length_zero.len(), 0)
    );
    assert_eq!(
        length_one_block_enc.len() as i64,
        EncryptSize(length_one_block.len(), 0)
    );
    assert_eq!(
        one_full_block_enc.len() as i64,
        EncryptSize(one_full_block.len(), 0)
    );
    assert_eq!(
        multiple_blocks_enc.len() as i64,
        EncryptSize(multiple_blocks.len(), 0)
    );
}

#[test]
fn test_hash_password_length() {
    let small_password = b"pass";
    let long_password = b"this is a very long and complicated password that is, I hope,\
     longer than the length of the actual hash. It also contains we1rd pa$$w0rd///s.\\";

    let small_password_hash: Vec<u8> =
        hash_password(small_password, 100, PasswordHashVersion::Latest)
            .unwrap()
            .into();
    let long_password_hash: Vec<u8> =
        hash_password(long_password, 2642, PasswordHashVersion::Latest)
            .unwrap()
            .into();

    assert_eq!(HashPasswordLength() as usize, small_password_hash.len());
    assert_eq!(HashPasswordLength() as usize, long_password_hash.len());
}

#[test]
fn test_key_exchange_length() {
    let bob_keypair = generate_keypair(KeyVersion::Latest);
    let alice_keypair = generate_keypair(KeyVersion::Latest);

    let private_bob: Vec<u8> = bob_keypair.private_key.into();
    let public_bob: Vec<u8> = bob_keypair.public_key.into();

    assert_eq!(GenerateKeyPairSize() as usize, private_bob.len());
    assert_eq!(GenerateKeyPairSize() as usize, public_bob.len());

    let private_bob = PrivateKey::try_from(private_bob.as_slice()).unwrap();
    let public_bob = PublicKey::try_from(public_bob.as_slice()).unwrap();

    let shared_bob = mix_key_exchange(&private_bob, &alice_keypair.public_key).unwrap();
    let shared_alice = mix_key_exchange(&alice_keypair.private_key, &public_bob).unwrap();

    assert_eq!(MixKeyExchangeSize() as usize, shared_bob.len());
    assert_eq!(MixKeyExchangeSize() as usize, shared_alice.len());
}

#[test]
fn test_get_default_argon2parameters_size() {
    assert_eq!(GetDefaultArgon2ParametersSize(), 46);
}

#[test]
fn test_get_default_argon2parameters() {
    let mut argon2_parameters_vec: Vec<u8> = vec![0u8; GetDefaultArgon2ParametersSize() as usize];
    let argon2_parameters_raw = argon2_parameters_vec.as_mut_ptr();

    unsafe {
        let result = GetDefaultArgon2Parameters(
            argon2_parameters_raw,
            GetDefaultArgon2ParametersSize() as usize,
        );
        assert_eq!(result, 0);
    }

    unsafe {
        let argon2_parameters = slice::from_raw_parts(
            argon2_parameters_raw,
            GetDefaultArgon2ParametersSize() as usize,
        );

        let _params = Argon2Parameters::try_from(argon2_parameters).unwrap();

        let defaults: Vec<u8> = (&Argon2Parameters::default()).into();
        let received: Vec<u8> = argon2_parameters.to_vec();

        // The -16 is to remove the salt, since it is random
        assert_eq!(
            defaults[..defaults.len() - 16],
            received[..received.len() - 16]
        );
    }
}

#[test]
fn test_decode() {
    fn get_decoded_base64_string_length(base64: &str) -> usize {
        if base64.is_empty() || base64.len() % 4 != 0 {
            return 0;
        }

        let mut pad_count = 0;

        for i in (base64.len() - 2..base64.len()).rev() {
            if base64.as_bytes()[i] == b'=' {
                pad_count += 1;
            }
        }

        (3 * (base64.len() / 4)) - pad_count
    }

    let b64string = "DQwCAAIAAgCIG9L2MTiumytn7H/p5I3aGVdhV3WUL4i8nIeMWIJ1YRbNQ6lEiQDAyfYhbs6gg1cD7+5Ft2Q5cm7ArsGfiFYWnscm1y7a8tAGfjFFTonzrg==";
    let mut decode_output_vec = vec![0u8; get_decoded_base64_string_length(b64string)];
    let decode_output = decode_output_vec.as_mut_ptr();

    unsafe {
        let res = Decode(
            b64string.as_ptr(),
            b64string.len(),
            decode_output,
            get_decoded_base64_string_length(b64string),
        );
        assert!(res > 0i64)
    }
}
