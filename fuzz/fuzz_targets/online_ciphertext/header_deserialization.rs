#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::online_ciphertext::OnlineCiphertextHeader;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = OnlineCiphertextHeader::try_from(data);
});
