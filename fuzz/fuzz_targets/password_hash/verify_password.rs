#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::password_hash::PasswordHash;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    hash: PasswordHash,
}

fuzz_target!(|data: Input| {
    // Hardcode 2 iterations so it won't be too CPU demanding.
    let _ = data.hash.verify_password(&data.data);
});
