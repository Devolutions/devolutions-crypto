#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use devolutions_crypto::ciphertext::Ciphertext;
use devolutions_crypto::key::PrivateKey;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Ciphertext,
    key: PrivateKey,
}

fuzz_target!(|data: Input| {
    let _ = data.data.decrypt_asymmetric(&data.key);
});
