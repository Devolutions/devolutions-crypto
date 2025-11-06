#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::utils::constant_time_equals;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    x: Vec<u8>,
    y: Vec<u8>,
}

fuzz_target!(|data: Input| {
    let _ = constant_time_equals(&data.x, &data.y);
});
