#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::key::{PrivateKey, SecretKey};
use devolutions_crypto::key_encapsulation::{EncapsulatedKey, decapsulate};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    encapsulated_key: EncapsulatedKey,
    key: PrivateKey,
}

fuzz_target!(|data: Input| {
    let _: Result<SecretKey, _> = decapsulate(&data.key, &data.encapsulated_key);
});
