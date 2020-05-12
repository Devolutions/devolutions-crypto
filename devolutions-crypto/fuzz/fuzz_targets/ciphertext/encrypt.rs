#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use devolutions_crypto::ciphertext::{ encrypt, CiphertextVersion };

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    key: Vec<u8>,
    version: CiphertextVersion,
}

fuzz_target!(|data: Input| {
    let _ = encrypt(&data.data, &data.key, data.version);
});
