#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::online_ciphertext::{OnlineCiphertextEncryptor, OnlineCiphertextVersion};

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    key: Vec<u8>,
    aad: Vec<u8>,
    chunk_size: u32,
    chunks: Vec<Vec<u8>>,
    version: OnlineCiphertextVersion,
}

fuzz_target!(|input: Input| {
    let Ok(mut encryptor) =
        OnlineCiphertextEncryptor::new(&input.key, &input.aad, input.chunk_size, input.version)
    else {
        return;
    };

    // Encrypt chunks
    for chunk in input
        .chunks
        .iter()
        .take(input.chunks.len().saturating_sub(1))
    {
        let _ = encryptor.encrypt_next_chunk(chunk, &[]);
    }

    // Encrypt last chunk if available
    if let Some(last_chunk) = input.chunks.last() {
        let _ = encryptor.encrypt_last_chunk(last_chunk, &[]);
    }
});
