#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::utils::validate_header;
use devolutions_crypto::DataType;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    header: Vec<u8>,
    data_type: DataType,
}

fuzz_target!(|input: Input| {
    let _ = validate_header(&input.header, input.data_type);
});
