#![allow(non_snake_case)]

//! FFI interface for use with other languages. Mostly used for C and C#.
//! # Safety
//! Note that this API is unsafe by nature: Rust can do a couple of check but cannot garantee
//!     the received pointers are valid. It is the job of the calling language to verify it passes
//!     the right pointers and length.
//! The Size functions must be called to get the required length of the returned array before
//!     calling it.

use super::utils;
use super::Argon2Parameters;
use super::DcDataBlob;
use super::DevoCryptoError;

use super::Result;

use std::convert::TryFrom as _;
use std::slice;

use zeroize::Zeroize as _;

use base64::{decode_config_slice, encode_config_slice, STANDARD};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Encrypt a data blob
/// # Arguments
///  * `data` - Pointer to the data to encrypt.
///  * `data_length` - Length of the data to encrypt.
///  * `key` - Pointer to the key to use to encrypt.
///  * `key_length` - Length of the key to use to encrypt.
///  * `result` - Pointer to the buffer to write the ciphertext to.
///  * `result_length` - Length of the buffer to write the ciphertext to. You can get the value by
///                         calling EncryptSize() beforehand.
///  * `version` - Version to use. Use 0 for the latest one.
/// # Returns
/// This returns the length of the ciphertext. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn Encrypt(
    data: *const u8,
    data_length: usize,
    key: *const u8,
    key_length: usize,
    result: *mut u8,
    result_length: usize,
    version: u16,
) -> i64 {
    if data.is_null() || key.is_null() || result.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    if result_length != EncryptSize(data_length, version) as usize {
        return DevoCryptoError::InvalidOutputLength.error_code();
    }

    let data = slice::from_raw_parts(data, data_length);
    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    let version = match version {
        0 => None,
        v => Some(v),
    };

    match DcDataBlob::encrypt(data, key, version) {
        Ok(res) => {
            let mut res: Vec<u8> = res.into();
            let length = res.len();
            result[0..length].copy_from_slice(&res);
            res.zeroize();
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
///  * `result` - Pointer to the buffer to write the ciphertext to.
///  * `result_length` - Length of the buffer to write the ciphertext to. You can get the value by
///                         calling EncryptAsymmetricSize() beforehand.
///  * `version` - Version to use. Use 0 for the latest one.
/// # Returns
/// This returns the length of the asymmetric ciphertext. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn EncryptAsymmetric(
    data: *const u8,
    data_length: usize,
    public_key: *const u8,
    public_key_length: usize,
    result: *mut u8,
    result_length: usize,
    version: u16,
) -> i64 {
    if data.is_null() || public_key.is_null() || result.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    if result_length != EncryptAsymmetricSize(data_length, version) as usize {
        return DevoCryptoError::InvalidOutputLength.error_code();
    }

    let data = slice::from_raw_parts(data, data_length);
    let public_key = DcDataBlob::try_from(slice::from_raw_parts(public_key, public_key_length));

    match public_key {
        Ok(public_key) => {
            let result = slice::from_raw_parts_mut(result, result_length);

            let version = match version {
                0 => None,
                v => Some(v),
            };

            match DcDataBlob::encrypt_asymmetric(data, &public_key, version) {
                Ok(res) => {
                    let mut res: Vec<u8> = res.into();
                    let length = res.len();

                    result[0..length].copy_from_slice(&res);
                    res.zeroize();
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
        _ => DevoCryptoError::UnknownVersion.error_code(),
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
        _ => DevoCryptoError::UnknownVersion.error_code(),
    }
}

/// Decrypt a data blob
/// # Arguments
///  * `data` - Pointer to the data to decrypt.
///  * `data_length` - Length of the data to decrypt.
///  * `key` - Pointer to the key to use to decrypt.
///  * `key_length` - Length of the key to use to decrypt.
///  * `result` - Pointer to the buffer to write the plaintext to.
///  * `result_length` - Length of the buffer to write the plaintext to.
///                     The safest size is the same size as the ciphertext.
/// # Returns
/// This returns the length of the plaintext. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn Decrypt(
    data: *const u8,
    data_length: usize,
    key: *const u8,
    key_length: usize,
    result: *mut u8,
    result_length: usize,
) -> i64 {
    if data.is_null() || key.is_null() || result.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let data = slice::from_raw_parts(data, data_length);
    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    match DcDataBlob::try_from(data) {
        Ok(res) => match res.decrypt(key) {
            Ok(mut res) => {
                if result.len() >= res.len() {
                    let length = res.len();
                    result[0..length].copy_from_slice(&res);
                    res.zeroize();
                    length as i64
                } else {
                    res.zeroize();
                    DevoCryptoError::InvalidOutputLength.error_code()
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
///  * `result` - Pointer to the buffer to write the plaintext to.
///  * `result_length` - Length of the buffer to write the plaintext to.
///                     The safest size is the same size as the ciphertext.
/// # Returns
/// This returns the length of the plaintext. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn DecryptAsymmetric(
    data: *const u8,
    data_length: usize,
    private_key: *const u8,
    private_key_length: usize,
    result: *mut u8,
    result_length: usize,
) -> i64 {
    if data.is_null() || private_key.is_null() || result.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let data = slice::from_raw_parts(data, data_length);
    let private_key = DcDataBlob::try_from(slice::from_raw_parts(private_key, private_key_length));

    match private_key {
        Ok(private_key) => {
            let result = slice::from_raw_parts_mut(result, result_length);

            match DcDataBlob::try_from(data) {
                Ok(res) => match res.decrypt_asymmetric(&private_key) {
                    Ok(mut res) => {
                        if result.len() >= res.len() {
                            let length = res.len();
                            result[0..length].copy_from_slice(&res);
                            res.zeroize();
                            length as i64
                        } else {
                            res.zeroize();
                            DevoCryptoError::InvalidOutputLength.error_code()
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn HashPassword(
    password: *const u8,
    password_length: usize,
    iterations: u32,
    result: *mut u8,
    result_length: usize,
) -> i64 {
    if password.is_null() || result.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    if result_length != HashPasswordLength() as usize {
        return DevoCryptoError::InvalidOutputLength.error_code();
    };

    let password = slice::from_raw_parts(password, password_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    match DcDataBlob::hash_password(password, iterations) {
        Ok(res) => {
            let mut res: Vec<u8> = res.into();
            let length = res.len();
            result[0..length].copy_from_slice(&res);
            res.zeroize();
            length as i64
        }
        Err(e) => e.error_code(),
    }
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn VerifyPassword(
    password: *const u8,
    password_length: usize,
    hash: *const u8,
    hash_length: usize,
) -> i64 {
    if password.is_null() || hash.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let password = slice::from_raw_parts(password, password_length);
    let hash = slice::from_raw_parts(hash, hash_length);

    match DcDataBlob::try_from(hash) {
        Ok(res) => match res.verify_password(password) {
            Ok(res) => {
                if res {
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn GenerateKeyPair(
    private: *mut u8,
    private_length: usize,
    public: *mut u8,
    public_length: usize,
) -> i64 {
    if private.is_null() || public.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    if private_length != GenerateKeyPairSize() as usize
        || public_length != GenerateKeyPairSize() as usize
    {
        return DevoCryptoError::InvalidOutputLength.error_code();
    }

    let private = slice::from_raw_parts_mut(private, private_length);
    let public = slice::from_raw_parts_mut(public, public_length);

    match DcDataBlob::generate_keypair() {
        Ok((priv_res, pub_res)) => {
            let mut priv_res: Vec<u8> = priv_res.into();
            let mut pub_res: Vec<u8> = pub_res.into();
            public[0..pub_res.len()].copy_from_slice(&pub_res);
            private[0..priv_res.len()].copy_from_slice(&priv_res);
            priv_res.zeroize();
            pub_res.zeroize();
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

/// Get the size of the keys in the derived key pair.
/// # Returns
/// Returns the length of the keys to input as `private_length`
///     and `public_length` in `DeriveKeyPair()`.
#[no_mangle]
pub extern "C" fn DeriveKeyPairSize() -> i64 {
    GenerateKeyPairSize()
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
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
        return DevoCryptoError::NullPointer.error_code();
    };

    if shared_size != MixKeyExchangeSize() as usize {
        return DevoCryptoError::InvalidOutputLength.error_code();
    }

    let public = slice::from_raw_parts(public, public_size);
    let private = slice::from_raw_parts(private, private_size);
    let shared = slice::from_raw_parts_mut(shared, shared_size);

    match (DcDataBlob::try_from(private), DcDataBlob::try_from(public)) {
        (Ok(private), Ok(public)) => match private.mix_key_exchange(&public) {
            Ok(mut res) => {
                shared[0..res.len()].copy_from_slice(&res);
                res.zeroize();
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn GenerateSharedKey(
    n_shares: u8,
    threshold: u8,
    length: usize,
    shares: *const *mut u8,
) -> i64 {
    if shares.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    match DcDataBlob::generate_shared_key(n_shares, threshold, length) {
        Ok(s) => {
            let shares = slice::from_raw_parts(shares, n_shares as usize);

            for (s, res_s) in s.into_iter().zip(shares) {
                if res_s.is_null() {
                    return DevoCryptoError::NullPointer.error_code();
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn JoinShares(
    n_shares: usize,
    share_length: usize,
    shares: *const *const u8,
    secret: *mut u8,
    secret_length: usize,
) -> i64 {
    if shares.is_null() || secret.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    if secret_length != JoinSharesSize(share_length) as usize {
        return DevoCryptoError::InvalidOutputLength.error_code();
    }

    let shares: Result<Vec<DcDataBlob>> = slice::from_raw_parts(shares, n_shares)
        .iter()
        .map(|s| DcDataBlob::try_from(slice::from_raw_parts(*s, share_length)))
        .collect();

    match shares {
        Ok(shares) => match DcDataBlob::join_shares(&shares) {
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn GenerateKey(key: *mut u8, key_length: usize) -> i64 {
    if key.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let key = slice::from_raw_parts_mut(key, key_length);

    let mut k = utils::generate_key(key_length);
    key.copy_from_slice(&k);
    k.zeroize();
    0
}

/// Derive a key to create a new one. Can be used with a password.
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn DeriveKey(
    key: *const u8,
    key_length: usize,
    salt: *const u8,
    salt_length: usize,
    niterations: usize,
    result: *mut u8,
    result_length: usize,
) -> i64 {
    if key.is_null() || result.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let salt = if salt.is_null() || salt_length == 0 {
        b""
    } else {
        slice::from_raw_parts(salt, salt_length)
    };

    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    let mut native_result = utils::derive_key(&key, &salt, niterations, result_length);
    result.copy_from_slice(&native_result);
    native_result.zeroize();
    0
}

/// Get the default Argon2Parameters struct values.
/// # Arguments
///  * argon2_parameters - Pointer to the output buffer.
///  * argon2_parameters_length - Length of the output buffer.
/// # Returns
/// Returns 0 if the operation is successful.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn GetDefaultArgon2Parameters(
    argon2_parameters: *mut u8,
    argon2_parameters_length: usize,
) -> i64 {
    let argon2_parameters = slice::from_raw_parts_mut(argon2_parameters, argon2_parameters_length);

    let argon2_parameters_raw: Vec<u8> = Argon2Parameters::default().into();
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

/// Derives a key pair from a password.
/// # Arguments
///  * password - Pointer to the password to derive.
///  * password_length - Length of the password to derive.
///  * parameters - Pointer to the argon2 parameters used for the derivation.
///  * parameters_length - Length of the argon2 parameters used for the derivation.
///  * private_key - Pointer to the resulting private key buffer.
///  * private_key_length - Length of the private key output buffer.
///  * public_key - Pointer to the resulting public key buffer.
///  * public_key_length - Length of the public key output buffer.
/// # Returns
/// Returns 0 if the operation is successful. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
/// # Safety
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn DeriveKeyPair(
    password: *const u8,
    password_length: usize,
    parameters: *const u8,
    parameters_length: usize,
    private_key: *mut u8,
    private_key_length: usize,
    public_key: *mut u8,
    public_key_length: usize,
) -> i64 {
    if password.is_null() || parameters.is_null() || private_key.is_null() || public_key.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    if private_key_length != DeriveKeyPairSize() as usize
        || public_key_length != DeriveKeyPairSize() as usize
    {
        return DevoCryptoError::InvalidOutputLength.error_code();
    }

    let password = slice::from_raw_parts(password, password_length);
    let private_key = slice::from_raw_parts_mut(private_key, private_key_length);
    let public_key = slice::from_raw_parts_mut(public_key, public_key_length);

    let parameters =
        Argon2Parameters::try_from(slice::from_raw_parts(parameters, parameters_length));

    let parameters = match parameters {
        Ok(x) => x,
        Err(e) => return e.error_code(),
    };

    match DcDataBlob::derive_keypair(password, &parameters) {
        Ok(keypairs) => {
            let private: Vec<u8> = keypairs.0.into();
            let public: Vec<u8> = keypairs.1.into();
            private_key.copy_from_slice(&private);
            public_key.copy_from_slice(&public);
            0
        }
        Err(e) => e.error_code(),
    }
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn Decode(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
) -> i64 {
    if input.is_null() || output.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let input = std::str::from_utf8_unchecked(slice::from_raw_parts(input, input_length));
    let mut output = slice::from_raw_parts_mut(output, output_length);

    match decode_config_slice(&input, STANDARD, &mut output) {
        Ok(res) => res as i64,
        Err(_e) => -1,
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn Encode(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
) -> i64 {
    if input.is_null() || output.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let input = slice::from_raw_parts(input, input_length);
    let mut output = slice::from_raw_parts_mut(output, output_length);

    encode_config_slice(&input, STANDARD, &mut output) as i64
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
/// This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers ans sizes.
#[no_mangle]
pub unsafe extern "C" fn Version(output: *mut u8, output_length: usize) -> i64 {
    if output.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let output = slice::from_raw_parts_mut(output, output_length);
    output.copy_from_slice(&VERSION.as_bytes());

    output.len() as i64
}

#[test]
fn test_encrypt_length() {
    let key = b"supersecret";
    let length_zero = b"";
    let length_one_block = b"hello";
    let one_full_block = b"0123456789abcdef";
    let multiple_blocks = b"0123456789abcdefghijkl";

    let length_zero_enc: Vec<u8> = DcDataBlob::encrypt(length_zero, key, None).unwrap().into();
    let length_one_block_enc: Vec<u8> = DcDataBlob::encrypt(length_one_block, key, None)
        .unwrap()
        .into();
    let one_full_block_enc: Vec<u8> = DcDataBlob::encrypt(one_full_block, key, None)
        .unwrap()
        .into();
    let multiple_blocks_enc: Vec<u8> = DcDataBlob::encrypt(multiple_blocks, key, None)
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

    let small_password_hash: Vec<u8> = DcDataBlob::hash_password(small_password, 100)
        .unwrap()
        .into();
    let long_password_hash: Vec<u8> = DcDataBlob::hash_password(long_password, 2642)
        .unwrap()
        .into();

    assert_eq!(HashPasswordLength() as usize, small_password_hash.len());
    assert_eq!(HashPasswordLength() as usize, long_password_hash.len());
}

#[test]
fn test_key_exchange_length() {
    let (private_bob, public_bob) = DcDataBlob::generate_keypair().unwrap();
    let (private_alice, public_alice) = DcDataBlob::generate_keypair().unwrap();

    let private_bob: Vec<u8> = private_bob.into();
    let public_bob: Vec<u8> = public_bob.into();

    assert_eq!(GenerateKeyPairSize() as usize, private_bob.len());
    assert_eq!(GenerateKeyPairSize() as usize, public_bob.len());

    let private_bob = DcDataBlob::try_from(private_bob.as_slice()).unwrap();
    let public_bob = DcDataBlob::try_from(public_bob.as_slice()).unwrap();

    let shared_bob = private_bob.mix_key_exchange(&public_alice).unwrap();
    let shared_alice = private_alice.mix_key_exchange(&public_bob).unwrap();

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

        let defaults: Vec<u8> = Argon2Parameters::default().into();
        let received: Vec<u8> = argon2_parameters.to_vec();

        // The -16 is to remove the salt, since it is random
        assert_eq!(
            defaults[..defaults.len() - 16],
            received[..received.len() - 16]
        );
    }
}

#[test]
fn test_derive_keypair() {
    let small_password = b"pass".to_vec();
    let long_password = b"this is a very long and complicated password that is, I hope,\
     longer than the length of the actual hash. It also contains we1rd pa$$w0rd///s.\\"
        .to_vec();

    let parameters: Vec<u8> = Argon2Parameters::default().into();

    let mut private_key_vec = vec![0u8; DeriveKeyPairSize() as usize];
    let private_key = private_key_vec.as_mut_ptr();
    let mut public_key_vec = vec![0u8; DeriveKeyPairSize() as usize];
    let public_key = public_key_vec.as_mut_ptr();

    unsafe {
        let result_small = DeriveKeyPair(
            small_password.as_ptr(),
            small_password.len(),
            parameters.as_ptr(),
            parameters.len(),
            private_key,
            DeriveKeyPairSize() as usize,
            public_key,
            DeriveKeyPairSize() as usize,
        );
        assert_eq!(0i64, result_small);
        let result_long = DeriveKeyPair(
            long_password.as_ptr(),
            long_password.len(),
            parameters.as_ptr(),
            parameters.len(),
            private_key,
            DeriveKeyPairSize() as usize,
            public_key,
            DeriveKeyPairSize() as usize,
        );
        assert_eq!(0i64, result_long);
    }

    let data = b"SomeData".to_vec();
    let encrypt_size = EncryptAsymmetricSize(data.len(), 2);

    let mut result_encrypt_vec = vec![0u8; encrypt_size as usize];
    let result_encrypt = result_encrypt_vec.as_mut_ptr();
    unsafe {
        let result_code_encrypt = EncryptAsymmetric(
            data.as_ptr(),
            data.len(),
            public_key,
            DeriveKeyPairSize() as usize,
            result_encrypt,
            encrypt_size as usize,
            2,
        );
        assert_eq!(encrypt_size, result_code_encrypt)
    }

    let mut result_decrypt_vec = vec![0u8; encrypt_size as usize];
    let result_decrypt = result_decrypt_vec.as_mut_ptr();
    unsafe {
        let result_code_decrypt = DecryptAsymmetric(
            result_encrypt,
            encrypt_size as usize,
            private_key,
            DeriveKeyPairSize() as usize,
            result_decrypt,
            encrypt_size as usize,
        );

        assert!(result_code_decrypt >= 0);

        let decrypt_data = slice::from_raw_parts_mut(result_decrypt, result_code_decrypt as usize);
        assert_eq!(data, decrypt_data);
    }
}
