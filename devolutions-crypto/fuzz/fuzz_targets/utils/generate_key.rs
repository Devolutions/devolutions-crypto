#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use devolutions_crypto::utils::generate_key;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    length: u16,
}

fuzz_target!(|data: Input| {
    let _ = generate_key(data.length.into());
});
