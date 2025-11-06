#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::ciphertext::Ciphertext;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Ciphertext,
    key: Vec<u8>,
    aad: Vec<u8>,
}

fuzz_target!(|data: Input| {
    let _ = data.data.decrypt_with_aad(&data.key, &data.aad);
});
