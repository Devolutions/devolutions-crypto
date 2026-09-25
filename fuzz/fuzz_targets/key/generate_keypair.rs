#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::key::{KeyVersion, generate_keypair};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    version: KeyVersion,
}

fuzz_target!(|data: Input| {
    let _ = generate_keypair(data.version);
});
