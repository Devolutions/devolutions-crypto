#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::derive_encrypt::KdfEncryptedData;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = KdfEncryptedData::try_from(data);
});
