#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::password_hash::PasswordHash;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = PasswordHash::try_from(data);
});
