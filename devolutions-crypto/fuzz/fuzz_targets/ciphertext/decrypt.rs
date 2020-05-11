#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use devolutions_crypto::ciphertext::Ciphertext;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Ciphertext,
    key: Vec<u8>,
}

fuzz_target!(|data: Input| {
    let _ = data.data.decrypt(&data.key);
});
