#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::utils::derive_key;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    input: Vec<u8>,
    salt: Vec<u8>,
    length: u8,
}

fuzz_target!(|data: Input| {
    let _ = derive_key(&data.input, &data.salt, 10, data.length.into());
});
