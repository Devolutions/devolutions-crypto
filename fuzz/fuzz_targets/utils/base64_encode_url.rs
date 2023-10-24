#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::utils::base64_encode_url;

fuzz_target!(|data: &[u8]| {
    let _ = base64_encode_url(data);
});
