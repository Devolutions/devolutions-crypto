#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::utils::scrypt_simple;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    password: Vec<u8>,
    salt: Vec<u8>,
    log_n: u8,
    r: u32,
    p: u32,
}

fuzz_target!(|input: Input| {
    // Clamp values to prevent excessive computation during fuzzing
    let log_n = input.log_n.clamp(1, 15); // 2^15 = 32768 max iterations
    let r = input.r.clamp(1, 8);
    let p = input.p.clamp(1, 4);

    // Limit input sizes for performance
    let password = if input.password.len() > 128 {
        &input.password[..128]
    } else {
        &input.password[..]
    };

    let salt = if input.salt.len() > 64 {
        &input.salt[..64]
    } else if input.salt.is_empty() {
        &[0u8; 8][..]
    } else {
        &input.salt[..]
    };

    let _ = scrypt_simple(password, salt, log_n, r, p);
});
