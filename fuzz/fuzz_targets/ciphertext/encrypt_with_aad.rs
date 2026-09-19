#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::ciphertext::{CiphertextVersion, encrypt_with_aad};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    key: Vec<u8>,
    aad: Vec<u8>,
    version: CiphertextVersion,
}

fuzz_target!(|data: Input| {
    let _ = encrypt_with_aad(&data.data, &data.key, &data.aad, data.version);
});
