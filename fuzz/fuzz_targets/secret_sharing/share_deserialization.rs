#![no_main]
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::secret_sharing::Share;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let _ = Share::try_from(data);
});
