#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::signing_key::SigningPublicKey;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = SigningPublicKey::try_from(data);
});
