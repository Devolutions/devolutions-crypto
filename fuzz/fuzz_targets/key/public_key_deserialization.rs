#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::key::PublicKey;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = PublicKey::try_from(data);
});
