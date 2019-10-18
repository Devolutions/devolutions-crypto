#![allow(non_snake_case)]

//! FFI interface for use with other languages. Mostly used for C and C#.
//! # Safety
//! Note that this API is unsafe by nature: Rust can do a couple of check but cannot garantee
//!     the received pointers are valid. It is the job of the calling language to verify it passes
//!     the right pointers and length.
//! The Size functions must be called to get the required length of the returned array before
//!     calling it.

use super::devocrypto;
use super::DcDataBlob;
use super::DevoCryptoError;

use std::convert::TryFrom as _;
use std::slice;

use zeroize::Zeroize as _;

use base64::{decode_config_slice, encode_config_slice, STANDARD};

/// Encrypt a data blob
/// # Arguments
///  * `data` - Pointer to the data to encrypt.
///  * `data_length` - Length of the data to encrypt.
///  * `key` - Pointer to the key to use to encrypt.
///  * `key_length` - Length of the key to use to encrypt.
///  * `result` - Pointer to the buffer to write the ciphertext to.
///  * `result_length` - Length of the buffer to write the ciphertext to. You can get the value by
///                         calling EncryptSize() beforehand.
/// # Returns
/// This returns the length of the ciphertext. If there is an error, it will return the
///     appropriate error code defined in DevoCryptoError.
#[no_mangle]
pub unsafe extern "C" fn Encrypt(
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

    if result_length != EncryptSize(data_length) as usize {
        return DevoCryptoError::InvalidOutputLength.error_code();
    }

    let data = slice::from_raw_parts(data, data_length);
    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    match DcDataBlob::encrypt(data, key) {
        Ok(res) => {
            let mut res: Vec<u8> = res.into();
            let length = res.len();
            result[0..length].copy_from_slice(&res);
            res.zeroize();
            length as i64
        },
        Err(e) => e.error_code(),
    }
}


/// Get the size of the resulting ciphertext.
/// # Arguments
///  * data_length - Length of the plaintext.
/// # Returns
/// Returns the length of the ciphertext to input as `result_length` in `Encrypt()`.
#[no_mangle]
pub extern "C" fn EncryptSize(data_length: usize) -> i64 {
    (8 + 24 + data_length + 16) as i64 // Header + nonce + data + Poly1305 tag
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
        Ok(res) => {
            match res.decrypt(key) {
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
                },
                Err(e) => e.error_code(),
            }
        },
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
        },
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
        Ok(res) => {
            match res.verify_password(password) {
                Ok(res) => {
                    if res {
                        1
                    } else {
                        0
                    }
                },
                Err(e) => e.error_code(),
            }
        },
        Err(e) => e.error_code(),
    }
}

/// Generate a key pair to perform a key exchange. Must be used with MixKey()
/// # Arguments
///  * `private` - Pointer to the buffer to write the private key to.
///  * `private_length` - Length of the buffer to write the private key to.
///                         You can get the value by calling `GenerateKeyExchangeSize()` beforehand.
///  * `public` - Pointer to the buffer to write the public key to.
///  * `public_length` - Length of the buffer to write the public key to.
///                         You can get the value by calling `GenerateKeyExchangeSize()` beforehand.
/// # Returns
/// Returns 0 if the generation worked. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
#[no_mangle]
pub unsafe extern "C" fn GenerateKeyExchange(
    private: *mut u8,
    private_length: usize,
    public: *mut u8,
    public_length: usize,
) -> i64 {
    if private.is_null() || public.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    if private_length != GenerateKeyExchangeSize() as usize
        || public_length != GenerateKeyExchangeSize() as usize {
        return DevoCryptoError::InvalidOutputLength.error_code();
    }

    let private = slice::from_raw_parts_mut(private, private_length);
    let public = slice::from_raw_parts_mut(public, public_length);

    match DcDataBlob::generate_key_exchange() {
        Ok((priv_res, pub_res)) => {
            let mut priv_res: Vec<u8> = priv_res.into();
            let mut pub_res: Vec<u8> = pub_res.into();
            public[0..pub_res.len()].copy_from_slice(&pub_res);
            private[0..priv_res.len()].copy_from_slice(&priv_res);
            priv_res.zeroize();
            pub_res.zeroize();
            0
        },
        Err(e) => e.error_code(),
    }
}

/// Get the size of the keys in the key exchange key pair.
/// # Returns
/// Returns the length of the keys to input as `private_length`
///     and `public_length` in `GenerateKeyExchange()`.
#[no_mangle]
pub extern "C" fn GenerateKeyExchangeSize() -> i64 {
    8 + 32 // header + key length
}


/// Generate a key pair to perform a key exchange. Must be used with MixKey().
/// # Arguments
///  * `private` - Pointer to the buffer to write the private key to.
///  * `private_length` - Length of the buffer to write the private key to.
///                         You can get the value by calling `GenerateKeyExchangeSize()` beforehand.
///  * `public` - Pointer to the buffer to write the public key to.
///  * `public_length` - Length of the buffer to write the public key to.
///                         You can get the value by calling `GenerateKeyExchangeSize()` beforehand.
/// # Returns
/// Returns 0 if the generation worked. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
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
        (Ok(private), Ok(public)) => {
            match private.mix_key_exchange(public) {
                Ok(mut res) => {
                    shared[0..res.len()].copy_from_slice(&res);
                    res.zeroize();
                    0
                },
                Err(e) => e.error_code(),
            }
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

/// Generate a key using a CSPRNG.
/// # Arguments
///  * key - Pointer to the buffer to fill with random values.
///  * key_length - Length of the buffer to fill.
/// # Returns
/// Returns 0 if the operation is successful. If there is an error,
///     it will return the appropriate error code defined in DevoCryptoError.
#[no_mangle]
pub unsafe extern "C" fn GenerateKey(key: *mut u8, key_length: usize) -> i64 {
    if key.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let key = slice::from_raw_parts_mut(key, key_length);

    match devocrypto::generate_key(key_length) {
        Ok(mut k) => {
            key.copy_from_slice(&k);
            k.zeroize();
            0
        }
        Err(e) => e.error_code(),
    }
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
    }
    else {
        slice::from_raw_parts(salt, salt_length)
    };

    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    let mut native_result = devocrypto::derive_key(&key, &salt, niterations, result_length);
    result.copy_from_slice(&native_result);
    native_result.zeroize();
    0
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
#[no_mangle]
pub unsafe extern "C" fn Decode(input: *const u8, input_length: usize, output: *mut u8 , output_length: usize ) -> i64 {
    if input.is_null() || output.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let input = std::str::from_utf8_unchecked(slice::from_raw_parts(input, input_length));
    let mut output = slice::from_raw_parts_mut(output, output_length);

    match decode_config_slice(&input, STANDARD, &mut output) {
        Ok(res) => {
            res as i64
        },
        Err(_e) =>
        {
            -1
        }
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
#[no_mangle]
pub unsafe extern "C" fn Encode(input: *const u8, input_length: usize, output: *mut u8 , output_length: usize ) -> i64 {
    if input.is_null() || output.is_null() {
        return DevoCryptoError::NullPointer.error_code();
    };

    let input = slice::from_raw_parts(input, input_length);
    let mut output = slice::from_raw_parts_mut(output, output_length);

    encode_config_slice(&input, STANDARD, &mut output) as i64
}

#[test]
fn test_encrypt_length() {
    let key = b"supersecret";
    let length_zero = b"";
    let length_one_block = b"hello";
    let one_full_block = b"0123456789abcdef";
    let multiple_blocks = b"0123456789abcdefghijkl";

    let length_zero_enc: Vec<u8> = DcDataBlob::encrypt(length_zero, key).unwrap().into();
    let length_one_block_enc: Vec<u8> = DcDataBlob::encrypt(length_one_block, key).unwrap().into();
    let one_full_block_enc: Vec<u8> = DcDataBlob::encrypt(one_full_block, key).unwrap().into();
    let multiple_blocks_enc: Vec<u8> = DcDataBlob::encrypt(multiple_blocks, key).unwrap().into();

    assert_eq!(length_zero_enc.len() as i64, EncryptSize(length_zero.len()));
    assert_eq!(length_one_block_enc.len() as i64, EncryptSize(length_one_block.len()));
    assert_eq!(one_full_block_enc.len() as i64, EncryptSize(one_full_block.len()));
    assert_eq!(multiple_blocks_enc.len() as i64, EncryptSize(multiple_blocks.len()));
}

#[test]
fn test_hash_password_length() {
    let small_password = b"pass";
    let long_password = b"this is a very long and complicated password that is, I hope,\
     longer than the length of the actual hash. It also contains we1rd pa$$w0rd///s.\\";

    let small_password_hash: Vec<u8> = DcDataBlob::hash_password(small_password, 100).unwrap().into();
    let long_password_hash: Vec<u8> = DcDataBlob::hash_password(long_password, 2642).unwrap().into();

    assert_eq!(HashPasswordLength() as usize, small_password_hash.len());
    assert_eq!(HashPasswordLength() as usize, long_password_hash.len());
}

#[test]
fn test_key_exchange_length() {
    let (private_bob, public_bob) = DcDataBlob::generate_key_exchange().unwrap();
    let (private_alice, public_alice) = DcDataBlob::generate_key_exchange().unwrap();

    let private_bob: Vec<u8> = private_bob.into();
    let public_bob: Vec<u8> = public_bob.into();

    assert_eq!(GenerateKeyExchangeSize() as usize, private_bob.len());
    assert_eq!(GenerateKeyExchangeSize() as usize, public_bob.len());

    let private_bob = DcDataBlob::try_from(private_bob.as_slice()).unwrap();
    let public_bob = DcDataBlob::try_from(public_bob.as_slice()).unwrap();

    let shared_bob = private_bob.mix_key_exchange(public_alice).unwrap();
    let shared_alice = private_alice.mix_key_exchange(public_bob).unwrap();

    assert_eq!(MixKeyExchangeSize() as usize, shared_bob.len());
    assert_eq!(MixKeyExchangeSize() as usize, shared_alice.len());
}
