#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::key::{mix_key_exchange, PrivateKey, PublicKey};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    private_key: PrivateKey,
    public_key: PublicKey,
}

fuzz_target!(|input: Input| {
    let _ = mix_key_exchange(&input.private_key, &input.public_key);
});
