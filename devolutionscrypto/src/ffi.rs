#![allow(non_snake_case)]

use super::devocrypto;
use super::DcDataBlob;

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
                -1
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
                        -1
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
                -1
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
        Err(_) => -1,
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
