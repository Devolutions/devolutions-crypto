#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use devolutions_crypto::key::PrivateKey;
use devolutions_crypto::online_ciphertext::OnlineCiphertextHeader;

use std::convert::TryFrom;

#[derive(Arbitrary, Clone, Debug)]
struct Input {
    header_data: Vec<u8>,
    private_key: PrivateKey,
    aad: Vec<u8>,
    encrypted_chunks: Vec<Vec<u8>>,
}

fuzz_target!(|input: Input| {
    let Ok(header) = OnlineCiphertextHeader::try_from(input.header_data.as_slice()) else {
        return;
    };

    let Ok(mut decryptor) = header.into_decryptor_asymmetric(&input.private_key, &input.aad) else {
        return;
    };

    // Decrypt chunks
    for chunk in input
        .encrypted_chunks
        .iter()
        .take(input.encrypted_chunks.len().saturating_sub(1))
    {
        let _ = decryptor.decrypt_next_chunk(chunk, &[]);
    }

    // Decrypt last chunk if available
    if let Some(last_chunk) = input.encrypted_chunks.last() {
        let _ = decryptor.decrypt_last_chunk(last_chunk, &[]);
    }
});
