#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use devolutions_crypto::ciphertext::{ encrypt_asymmetric, CiphertextVersion };
use devolutions_crypto::key::PublicKey;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    key: PublicKey,
    version: CiphertextVersion,
}

fuzz_target!(|data: Input| {
    let _ = encrypt_asymmetric(&data.data, &data.key, data.version);
});
