#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::signature::{sign, SignatureVersion};
use devolutions_crypto::signing_key::SigningKeyPair;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    keypair: SigningKeyPair,
    version: SignatureVersion,
}

fuzz_target!(|input: Input| {
    let _ = sign(&input.data, &input.keypair, input.version);
});
