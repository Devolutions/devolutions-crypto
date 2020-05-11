#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::utils::base64_encode;

fuzz_target!(|data: &[u8]| {
    let _ = base64_encode(data);
});
