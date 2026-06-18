#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::derive_encrypt::encrypt_with_password_and_aad;
use devolutions_crypto::key_derivation::Argon2;
use devolutions_crypto::{Argon2Parameters, CiphertextVersion};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    data: Vec<u8>,
    password: Vec<u8>,
    aad: Vec<u8>,
    decrypt_password: Vec<u8>,
    decrypt_aad: Vec<u8>,
    length: u32,
    lanes: u32,
    memory: u32,
    iterations: u32,
    salt: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Clamp Argon2 parameters to keep key derivation cheap enough for fuzzing.
    let length = input.length.clamp(1, 128);
    let lanes = input.lanes.clamp(1, 16);
    let memory = input.memory.clamp(8, 65536);
    let iterations = input.iterations.clamp(1, 10);

    // Use only small salts for fuzzing performance.
    let salt = if input.salt.len() > 64 {
        &input.salt[..64]
    } else if input.salt.is_empty() {
        &[0u8; 8][..]
    } else {
        &input.salt[..]
    };

    let parameters = Argon2Parameters::builder()
        .length(length)
        .lanes(lanes)
        .memory(memory)
        .iterations(iterations)
        .salt(salt.to_vec())
        .build();

    let derivation_parameters = Argon2::with_params(parameters).parameters();

    let blob = match encrypt_with_password_and_aad(
        &input.data,
        &input.password,
        &input.aad,
        derivation_parameters,
        CiphertextVersion::Latest,
    ) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Exercise the decrypt path with both the correct and a fuzzed password/AAD.
    let _ = blob.decrypt_with_password_and_aad(&input.password, &input.aad);
    let _ = blob.decrypt_with_password_and_aad(&input.decrypt_password, &input.decrypt_aad);
});
