#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::Argon2Parameters;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = Argon2Parameters::try_from(data);
});
