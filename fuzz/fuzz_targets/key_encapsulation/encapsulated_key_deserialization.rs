#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::key_encapsulation::EncapsulatedKey;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = EncapsulatedKey::try_from(data);
});
