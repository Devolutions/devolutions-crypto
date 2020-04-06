#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use devolutions_crypto::password_hash::{ hash_password, PasswordHashVersion };

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    version: PasswordHashVersion,
}

fuzz_target!(|data: Input| {
    // Hardcode 2 iterations so it won't be too CPU demanding.
    let _ = hash_password(&data.data, 2, data.version);
});
