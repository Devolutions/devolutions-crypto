#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::signature::Signature;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = Signature::try_from(data);
});
