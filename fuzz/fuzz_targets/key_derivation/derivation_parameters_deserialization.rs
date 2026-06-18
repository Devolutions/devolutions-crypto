#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::key_derivation::DerivationParameters;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = DerivationParameters::try_from(data);
});
