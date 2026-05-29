#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::password_hash::{hash_password, PasswordHashVersion};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    version: PasswordHashVersion,
}

fuzz_target!(|data: Input| {
    let _ = hash_password(&data.data, data.version);
});
