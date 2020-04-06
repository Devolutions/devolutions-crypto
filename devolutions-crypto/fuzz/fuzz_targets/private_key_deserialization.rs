#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::key::PrivateKey;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = PrivateKey::try_from(data);
});
