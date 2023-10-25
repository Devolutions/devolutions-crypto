#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::utils::base64_decode_url;

fuzz_target!(|data: String| {
    let _ = base64_decode_url(&data);
});
