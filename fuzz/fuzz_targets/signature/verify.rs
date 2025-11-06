#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::signature::Signature;
use devolutions_crypto::signing_key::SigningPublicKey;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    signature: Signature,
    public_key: SigningPublicKey,
}

fuzz_target!(|input: Input| {
    let _ = input.signature.verify(&input.data, &input.public_key);
});
