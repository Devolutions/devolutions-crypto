#![allow(non_snake_case)]

use super::devocrypto;
use super::DcDataBlob;
use super::DevoCryptoError;

use std::convert::TryFrom as _;

use libc::{size_t, uint8_t};
use std::slice;

#[no_mangle]
pub unsafe extern "C" fn Encrypt(
    data: *const uint8_t,
    data_length: size_t,
    key: *const uint8_t,
    key_length: size_t,
    result: *mut uint8_t,
    result_length: size_t,
) -> i64 {
    assert!(!data.is_null());
    assert!(!key.is_null());
    assert!(!result.is_null());

    let data = slice::from_raw_parts(data, data_length);
    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    match DcDataBlob::encrypt(data, key) {
        Ok(res) => {
            let res: Vec<u8> = res.into();
            if result.len() >= res.len() {
                result[0..res.len()].copy_from_slice(&res);
                res.len() as i64
            } else {
                DevoCryptoError::InvalidLength.error_code()
            }
        },
        Err(e) => e.error_code(),
    }
}

#[no_mangle]
pub extern "C" fn EncryptSize(data_length: size_t) -> i64 {
    (8 + 16 + (data_length / 16 + 1) * 16 + 32) as i64 // Header + IV + data(padded to 16) + HMAC
}

#[no_mangle]
pub unsafe extern "C" fn Decrypt(
    data: *const uint8_t,
    data_length: size_t,
    key: *const uint8_t,
    key_length: size_t,
    result: *mut uint8_t,
    result_length: size_t,
) -> i64 {
    assert!(!data.is_null());
    assert!(!key.is_null());
    assert!(!result.is_null());

    let data = slice::from_raw_parts(data, data_length);
    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    match DcDataBlob::try_from(data) {
        Ok(res) => {
            match res.decrypt(key) {
                Ok(res) => {
                    if result.len() >= res.len() {
                        result[0..res.len()].copy_from_slice(&res);
                        res.len() as i64
                    } else {
                        DevoCryptoError::InvalidLength.error_code()
                    }
                },
                Err(e) => e.error_code(),
            }
        },
        Err(e) => e.error_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn HashPassword(
    password: *const uint8_t,
    password_length: size_t,
    iterations: u32,
    result: *mut uint8_t,
    result_length: size_t,
) -> i64 {
    assert!(!password.is_null());
    assert!(!result.is_null());

    let password = slice::from_raw_parts(password, password_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    match DcDataBlob::hash_password(password, iterations) {
        Ok(res) => {
            let res: Vec<u8> = res.into();
            if result.len() >= res.len() {
                result[0..res.len()].copy_from_slice(&res);
                res.len() as i64
            } else {
                DevoCryptoError::InvalidLength.error_code()
            }
        },
        Err(e) => e.error_code(),
    }
}

#[no_mangle]
pub extern "C" fn HashPasswordLength() -> i64 {
    8 + 4 + 32 + 32 // Header + iterations + salt + hash
}

#[no_mangle]
pub unsafe extern "C" fn VerifyPassword(
    password: *const uint8_t,
    password_length: size_t,
    hash: *const uint8_t,
    hash_length: size_t,
) -> i64 {
    assert!(!password.is_null());
    assert!(!hash.is_null());

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

#[no_mangle]
pub unsafe extern "C" fn GenerateKeyExchange(
    private: *mut uint8_t,
    private_size: size_t,
    public: *mut uint8_t,
    public_size: size_t,
) -> i64 {
    assert!(!private.is_null());
    assert!(!public.is_null());
    assert_eq!(private_size, 32 + 8);
    assert_eq!(public_size, 32 + 8);

    let private = slice::from_raw_parts_mut(private, private_size);
    let public = slice::from_raw_parts_mut(public, public_size);

    match DcDataBlob::generate_key_exchange() {
        Ok((priv_res, pub_res)) => {
            let priv_res: Vec<u8> = priv_res.into();
            let pub_res: Vec<u8> = pub_res.into();
            public[0..pub_res.len()].copy_from_slice(&pub_res);
            private[0..priv_res.len()].copy_from_slice(&priv_res);
            0
        },
        Err(e) => e.error_code(),
    }
}

#[no_mangle]
pub extern "C" fn GenerateKeyExchangeSize() -> i64 {
    8 + 32 // header + key length
}

#[no_mangle]
pub unsafe extern "C" fn MixKeyExchange(
    public: *const uint8_t,
    public_size: size_t,
    private: *const uint8_t,
    private_size: size_t,
    shared: *mut uint8_t,
    shared_size: size_t,
) -> i64 {
    assert!(!public.is_null());
    assert!(!private.is_null());
    assert!(!shared.is_null());
    assert_eq!(public_size, 32 + 8);
    assert_eq!(private_size, 32 + 8);
    assert_eq!(shared_size, 32);

    let public = slice::from_raw_parts(public, public_size);
    let private = slice::from_raw_parts(private, private_size);
    let shared = slice::from_raw_parts_mut(shared, shared_size);

    match (DcDataBlob::try_from(private), DcDataBlob::try_from(public)) {
        (Ok(private), Ok(public)) => {
            match private.mix_key_exchange(public) {
                Ok(res) => {
                    shared[0..res.len()].copy_from_slice(&res);
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

#[no_mangle]
pub extern "C" fn MixKeyExchangeSize() -> i64 {
    32
}

#[no_mangle]
pub unsafe extern "C" fn GenerateKey(key: *mut uint8_t, key_length: size_t) -> i64 {
    assert!(!key.is_null());
    let key = slice::from_raw_parts_mut(key, key_length);

    match devocrypto::generate_key(key_length) {
        Ok(k) => {
            key.copy_from_slice(&k);
            0
        }
        Err(e) => e.error_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn DeriveKey(
    key: *const uint8_t,
    key_length: size_t,
    salt: *const uint8_t,
    salt_length: size_t,
    niterations: usize,
    result: *mut uint8_t,
    result_length: size_t,
) -> i64 {
    assert!(!key.is_null());
    assert!(!result.is_null());

    let salt = if salt.is_null() {
        b""
    }
    else {
        slice::from_raw_parts(salt, salt_length)
    };

    let key = slice::from_raw_parts(key, key_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    result.copy_from_slice(&devocrypto::derive_key(&key, &salt, niterations, result_length));
    0
}

#[no_mangle]
pub extern "C" fn KeySize() -> u32 {
    256
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
