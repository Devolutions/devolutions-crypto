use crate::bastion::Error;
use block_padding::{Padding, Pkcs7};
use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const AAD_MAGIC_NUMBER: [u8; 4] = [0x53, 0x0A, 0x0F, 0x0E];
pub const SAFE_PAYLOAD_PREFIX: &str = "|~Safe~|";
pub const DEFAULT_BLOCK_SIZE: usize = 32;

/// Encrypts field-level content using default padding size.
///
/// See `encrypt_field_with_block_size` for details.
pub fn encrypt_field(master_key_id: Uuid, key: &[u8], content: &[u8]) -> Result<String, Error> {
    encrypt_field_with_block_size(master_key_id, key, content, DEFAULT_BLOCK_SIZE)
}

/// Encrypts field-level content using provided padding size.
///
/// - Output is the encrypted content in Bastion safe Field Value Format (ie: |~Safe~|k1AjQZYciYvlPmJMnHjbb…)
///
/// # Internals
///
/// - AAD is composed of a 4-byte magic number, a 4-byte reserved field and the master key UUID in big-endian binary format.
/// - A 24-byte nonce is randomly generated.
/// - Content is padded using PKCS#7 padding mode.
/// - Encryption using XChaCha2020-Poly1035.
/// - Output is a buffer such as `[magic number (4) | reserved (4) | UUID (16) | nonce (24) | Ciphertext (variable) | Tag (16)]`
///     encoded in Bastion safe Field Value Format.
pub fn encrypt_field_with_block_size(
    master_key_id: Uuid,
    key: &[u8],
    content: &[u8],
    block_size: usize,
) -> Result<String, Error> {
    use rand::rngs::OsRng;
    use rand::Fill;

    let block_start = (content.len() / block_size) * block_size;
    let plaintext_len = block_start + block_size;
    let total_len = AAD_SIZE + NONCE_SIZE + plaintext_len + TAG_SIZE;
    let mut buffer = Zeroizing::new(vec![0u8; total_len]);

    // Associated data [magic number (4) | reserved (4) | UUID (16)]
    let (aad, rest) = buffer.split_at_mut(AAD_SIZE);
    {
        let (aad_magic, aad_rest) = aad.split_at_mut(AAD_MAGIC_NUMBER_SIZE);
        aad_magic.copy_from_slice(&AAD_MAGIC_NUMBER);
        let (aad_reserved, aad_uuid) = aad_rest.split_at_mut(AAD_RESERVED_SIZE);
        aad_reserved.copy_from_slice(&[0, 0, 0, 0]); // useless, but just to be extra safe…
        aad_uuid.copy_from_slice(master_key_id.as_bytes());
    }

    // Nonce
    let (nonce, rest) = rest.split_at_mut(NONCE_SIZE);
    nonce.try_fill(&mut OsRng)?;
    let nonce = XNonce::from_slice(nonce);

    // Actual data
    let (data, rest) = rest.split_at_mut(rest.len() - TAG_SIZE);
    data[..content.len()].copy_from_slice(&content);

    // In-place pad operation
    Pkcs7::pad_block(&mut data[block_start..], content.len() - block_start)
        .map_err(|_| Error::PadOperation)?;

    // In-place encryption
    let key = Key::from_slice(key);
    let aead = XChaCha20Poly1305::new(key);
    let tag = aead
        .encrypt_in_place_detached(&nonce, aad, data)
        .map_err(|_| Error::XChaCha20)?;

    // Finally, write tag
    rest.copy_from_slice(&tag);

    // Our final payload (ie: |~Safe~|k1AjQZYciYvlPmJMnHjbb…)
    let mut final_payload = String::from(SAFE_PAYLOAD_PREFIX);
    base64::encode_config_buf(&*buffer, base64::STANDARD, &mut final_payload);

    Ok(final_payload)
}

/// Decrypts field-level content.
///
/// - Input is the encrypted key encoded in base64.
/// - Master Key ID is used for early key mismatch detection.
/// - Output is decrypted field content.
///
/// # Internals
///
/// - Decryption is done using XChaCha2020-Poly1035.
/// - Data layout is assumed to be the same as described in `encrypt_field_with_block_size`.
pub fn decrypt_field(
    master_key_id: Uuid,
    key: &[u8],
    encrypted_content: &str,
) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::aead::Tag;

    const MIN_SIZE: usize = AAD_SIZE + NONCE_SIZE + 1 + TAG_SIZE;

    let mut buffer = Zeroizing::new(base64::decode_config(
        &encrypted_content[SAFE_PAYLOAD_PREFIX.len()..],
        base64::STANDARD,
    )?);

    if buffer.len() < MIN_SIZE {
        return Err(Error::InvalidSize { got: buffer.len() });
    }

    let (aad, rest) = buffer.as_mut_slice().split_at_mut(AAD_SIZE);
    {
        // Associated data sanity checks

        let (aad_magic, aad_rest) = aad.split_at(AAD_MAGIC_NUMBER_SIZE);
        if aad_magic != AAD_MAGIC_NUMBER {
            return Err(Error::InvalidMagicNumber);
        }

        let (_aad_reserved, uuid) = aad_rest.split_at(AAD_RESERVED_SIZE);
        let found_master_key_id =
            Uuid::from_slice(&uuid[..16]).expect("buffer contains enough bytes");
        if master_key_id != found_master_key_id {
            return Err(Error::MasterKeyIdMismatch {
                expected: master_key_id,
                found: found_master_key_id,
            });
        }
    }

    let (nonce, rest) = rest.split_at_mut(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce);

    let (data, tag) = rest.split_at_mut(rest.len() - TAG_SIZE);

    let tag = Tag::<<XChaCha20Poly1305 as AeadInPlace>::TagSize>::from_slice(tag);

    let key = Key::from_slice(key);
    let aead = XChaCha20Poly1305::new(key);
    aead.decrypt_in_place_detached(nonce, aad, data, tag)
        .map_err(|_| Error::XChaCha20)?;

    // In-place unpad operation
    // Here, invalid padding would raise same error as chacha decryption (to prevent padding oracle).
    // However, it is not expected to actually fail.
    let decoded_payload = Pkcs7::unpad(data).map_err(|_| Error::XChaCha20)?;

    Ok(decoded_payload.to_vec())
}

const AAD_SIZE: usize = 24;
const AAD_MAGIC_NUMBER_SIZE: usize = 4;
const AAD_RESERVED_SIZE: usize = 4;

const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCE_KEY: &[u8] = &[
        189, 72, 50, 73, 241, 119, 140, 134, 238, 246, 196, 220, 22, 110, 240, 26, 66, 132, 74, 67,
        250, 203, 21, 31, 138, 56, 229, 130, 252, 157, 13, 32,
    ];
    const MASTER_KEY_ID: Uuid = Uuid::from_u128(512);
    const FIELD: &[u8] = b"Halt and Catch Fire";

    #[test]
    fn field_value_format() {
        let encrypted_field = encrypt_field(MASTER_KEY_ID, RESOURCE_KEY, FIELD).unwrap();
        assert!(encrypted_field.starts_with(SAFE_PAYLOAD_PREFIX));
        base64::decode(&encrypted_field[SAFE_PAYLOAD_PREFIX.len()..]).unwrap();
    }

    #[test]
    fn decrypt() {
        let encrypted_field = "|~Safe~|UwoPDgAAAAAAAAAAAAAAAAAAAAAAAAIA7hWOG8Vhjep9QBqwkiZhkoSDj+aIDuESmFmfV8O6w9QKWQvSMg4h3CvJgvAKNsSOs7DRgbAPsSDHWTrSam1NdozREXiOARW6";
        let decrypted_field = decrypt_field(MASTER_KEY_ID, RESOURCE_KEY, encrypted_field).unwrap();
        assert_eq!(decrypted_field, FIELD);
    }

    #[test]
    fn encrypt_decrypt() {
        let encrypted_field = encrypt_field(MASTER_KEY_ID, RESOURCE_KEY, FIELD).unwrap();
        let decrypted_field = decrypt_field(MASTER_KEY_ID, RESOURCE_KEY, &encrypted_field).unwrap();
        assert_eq!(decrypted_field, FIELD);
    }

    #[test]
    fn invalid_size_err() {
        let e = decrypt_field(MASTER_KEY_ID, &[0], "|~Safe~|cGFzc3dvcmQ=")
            .err()
            .unwrap();
        assert!(matches!(e, Error::InvalidSize { got: 8 }));
    }

    #[test]
    fn invalid_master_key_id_err() {
        let encrypted_field = "|~Safe~|UwoPDgAAAAAAAAAAAAAAAAAAAAAAAAIA7hWOG8Vhjep9QBqwkiZhkoSDj+aIDuESmFmfV8O6w9QKWQvSMg4h3CvJgvAKNsSOs7DRgbAPsSDHWTrSam1NdozREXiOARW6";
        let e = decrypt_field(Uuid::from_u128(1024), RESOURCE_KEY, encrypted_field)
            .err()
            .unwrap();
        assert!(matches!(e, Error::MasterKeyIdMismatch { .. }));
    }
}
