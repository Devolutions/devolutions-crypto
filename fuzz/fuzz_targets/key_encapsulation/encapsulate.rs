#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::key::PublicKey;
use devolutions_crypto::key_encapsulation::{KeyEncapsulationVersion, encapsulate};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    key: PublicKey,
    version: KeyEncapsulationVersion,
}

fuzz_target!(|data: Input| {
    let _ = encapsulate(&data.key, data.version);
});
