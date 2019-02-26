#![allow(non_snake_case)]

use super::devocrypto;
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

    match devocrypto::encrypt(data, key) {
        Ok(res) => {
            if result.len() >= res.len() {
                result[0..res.len()].copy_from_slice(&res);
                res.len() as i64
            } else {
                -1
            }
        }
        Err(_) => -1,
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

    match devocrypto::decrypt(data, key) {
        Ok(res) => {
            if result.len() >= res.len() {
                result[0..res.len()].copy_from_slice(&res);
                res.len() as i64
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn HashPassword(
    password: *const uint8_t,
    password_length: size_t,
    niterations: u32,
    result: *mut uint8_t,
    result_length: size_t,
) -> i64 {
    assert!(!password.is_null());
    assert!(!result.is_null());

    let password = slice::from_raw_parts(password, password_length);
    let result = slice::from_raw_parts_mut(result, result_length);

    match devocrypto::hash_password(password, niterations) {
        Ok(res) => {
            if result.len() >= res.len() {
                result[0..res.len()].copy_from_slice(&res);
                res.len() as i64
            } else {
                -1
            }
        }
        Err(_) => -1,
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

    match devocrypto::verify_password(password, hash) {
        Ok(res) => {
            if res {
                1
            } else {
                0
            }
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn GenerateKeyExchange(
    public: *mut uint8_t,
    public_size: size_t,
    private: *mut uint8_t,
    private_size: size_t,
) -> i64 {
    assert!(!public.is_null());
    assert!(!private.is_null());
    assert_eq!(public_size, 32 + 8);
    assert_eq!(private_size, 32 + 8);

    let public = slice::from_raw_parts_mut(public, public_size);
    let private = slice::from_raw_parts_mut(private, private_size);

    match devocrypto::generate_key_exchange() {
        Ok(res) => {
            let (pub_res, priv_res) = res;
            public[0..pub_res.len()].copy_from_slice(&pub_res);
            private[0..priv_res.len()].copy_from_slice(&priv_res);
            0
        },
        Err(_) => -1
    }
}

#[no_mangle]
pub extern "C" fn GenerateKeyExchangeSize() -> i64 {
    8 + 32 // header + key lenght
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

    let shared_vec = devocrypto::mix_key_exchange(&public, &private).unwrap();
    shared[0..shared_vec.len()].copy_from_slice(&shared_vec);
    0
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
        slice::from_raw_parts(salt, salt_length);
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
fn password_test() {
    // Test hash length
    let pass = "averystrongpassword".as_bytes();
    let niterations = 1234u32;

    let hash = devocrypto::hash_password(pass, niterations).unwrap();

    assert_eq!(hash.len(), HashPasswordLength() as usize);
}

