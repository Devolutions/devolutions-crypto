#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::ciphertext::Ciphertext;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = Ciphertext::try_from(data);
});
