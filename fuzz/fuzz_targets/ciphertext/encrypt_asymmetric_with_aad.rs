#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::ciphertext::{encrypt_asymmetric_with_aad, CiphertextVersion};
use devolutions_crypto::key::PublicKey;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    key: PublicKey,
    aad: Vec<u8>,
    version: CiphertextVersion,
}

fuzz_target!(|data: Input| {
    let _ = encrypt_asymmetric_with_aad(&data.data, &data.key, &data.aad, data.version);
});
