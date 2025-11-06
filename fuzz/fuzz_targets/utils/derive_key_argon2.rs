#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::utils::derive_key_argon2;
use devolutions_crypto::Argon2Parameters;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    key: Vec<u8>,
    length: u32,
    lanes: u32,
    memory: u32,
    iterations: u32,
    salt: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Clamp values to reasonable ranges to avoid excessive computation
    let length = input.length.clamp(1, 128);
    let lanes = input.lanes.clamp(1, 16);
    let memory = input.memory.clamp(8, 65536);
    let iterations = input.iterations.clamp(1, 10);

    // Use only small salts for fuzzing performance
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

    let _ = derive_key_argon2(&input.key, &parameters);
});
