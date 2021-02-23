use crate::bastion::Error;
use uuid::Uuid;
use x25519_dalek::EphemeralSecret;
use zeroize::{Zeroize, Zeroizing};

pub use x25519_dalek::PublicKey;

/// Wraps shared secret produced by key exchange
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Constructs `SharedSecret` from a slice of bytes whose len is exactly 32.
    /// Input slice is zeroized.
    pub fn from_slice_mut(bytes: &mut [u8]) -> Result<Self, Error> {
        use core::convert::TryFrom;
        let array =
            <[u8; 32]>::try_from(&*bytes).map_err(|_| Error::InvalidSize { got: bytes.len() })?;
        bytes.zeroize();
        Ok(Self(array))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SharedSecret {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

/// Basically wraps `x25519_dalek`
pub struct KeyExchange {
    /// Send this to peer.
    pub public_key: PublicKey,

    /// Hidden: this should not be shared.
    /// Good to know: this type is `Zeroize` on `Drop`.
    secret: EphemeralSecret,
}

impl KeyExchange {
    pub fn init() -> Self {
        use rand_core::OsRng;

        let secret = EphemeralSecret::new(OsRng);
        Self {
            public_key: PublicKey::from(&secret),
            secret,
        }
    }

    pub fn into_shared_secret(self, peer_public_key: &PublicKey) -> SharedSecret {
        let shared = self.secret.diffie_hellman(peer_public_key);
        SharedSecret(shared.to_bytes())
    }
}

/// Encrypts symmetric key to be sent over the wire using shared secret.
///
/// - Output is the encrypted key encoded in base64.
///
/// # Internals
///
/// - AAD is the CSC UUID in big-endian binary format.
/// - A 24-byte nonce is randomly generated.
/// - Symmetric key (our plaintext) is encrypted using XChaCha2020-Poly1035.
/// - Output is a buffer such as `[AAD (16) | nonce (24) | Ciphertext (variable) | Tag (16)]`
///     encoded in standard base64.
pub fn encrypt_key(
    shared_key: &SharedSecret,
    csc_uuid: Uuid,
    symmetric_key_to_share: &[u8],
) -> Result<String, Error> {
    use chacha20poly1305::aead::{AeadInPlace, NewAead};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
    use rand::rngs::OsRng;
    use rand::Fill;

    let aad_start = 0;
    let nonce_start = aad_start + AAD_SIZE;
    let data_start = nonce_start + NONCE_SIZE;
    let tag_start = data_start + symmetric_key_to_share.len();
    let total_len = tag_start + TAG_SIZE;

    let mut buffer = Zeroizing::new(vec![0u8; total_len]);

    // Associated data
    let (aad, rest) = buffer.split_at_mut(AAD_SIZE);
    aad.copy_from_slice(csc_uuid.as_bytes());

    // Nonce
    let (nonce, rest) = rest.split_at_mut(NONCE_SIZE);
    nonce.try_fill(&mut OsRng)?;
    let nonce = XNonce::from_slice(nonce);

    // Actual data
    let (data, rest) = rest.split_at_mut(rest.len() - TAG_SIZE);
    data.copy_from_slice(symmetric_key_to_share);

    // In-place encryption
    let key = Key::from_slice(&shared_key.0);
    let aead = XChaCha20Poly1305::new(key);
    let tag = aead
        .encrypt_in_place_detached(&nonce, aad, data)
        .map_err(|_| Error::XChaCha20)?;

    // Tag
    rest.copy_from_slice(&tag);

    Ok(base64::encode_config(&*buffer, base64::STANDARD))
}

/// Decrypts symmetric key using shared secret.
///
/// - Input is the encrypted key encoded in base64.
/// - Output is a tuple composed of CSC UUID and decrypted symmetric key.
///
/// # Internals
///
/// - Decryption is done using XChaCha2020-Poly1035.
/// - Data layout is assumed to be the same as described in `encrypt_key`.
pub fn decrypt_key(
    shared_key: &SharedSecret,
    encrypted_symmetric_key: &str,
) -> Result<(Uuid, Vec<u8>), Error> {
    use chacha20poly1305::aead::{AeadInPlace, NewAead, Tag};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

    const MIN_SIZE: usize = AAD_SIZE + NONCE_SIZE + 1 + TAG_SIZE;

    let mut buffer = Zeroizing::new(base64::decode_config(
        encrypted_symmetric_key,
        base64::STANDARD,
    )?);

    if buffer.len() < MIN_SIZE {
        return Err(Error::InvalidSize { got: buffer.len() });
    }

    let (aad, rest) = buffer.as_mut_slice().split_at_mut(AAD_SIZE);
    let (nonce, rest) = rest.split_at_mut(NONCE_SIZE);
    let (data, tag) = rest.split_at_mut(rest.len() - TAG_SIZE);

    let nonce = XNonce::from_slice(nonce);
    let tag = Tag::<<XChaCha20Poly1305 as AeadInPlace>::TagSize>::from_slice(tag);

    let key = Key::from_slice(&shared_key.0);
    let aead = XChaCha20Poly1305::new(key);
    aead.decrypt_in_place_detached(nonce, aad, data, tag)
        .map_err(|_| Error::XChaCha20)?;

    let csc_id = Uuid::from_slice(&aad[..16]).expect("buffer contains enough bytes");

    Ok((csc_id, data.to_vec()))
}

const AAD_SIZE: usize = 16;
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    use either::Either;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::thread;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    type Msg = Either<PublicKey, String>;

    const SOME_KEY: &[u8] = &[
        189, 72, 50, 73, 241, 119, 140, 134, 238, 246, 196, 220, 22, 110, 240, 26, 66, 132, 74, 67,
        250, 203, 21, 31, 138, 56, 229, 130, 252, 157, 13, 32,
    ];

    const CSC_ID: Uuid = Uuid::from_u128(256);

    fn client(tx: Sender<Msg>, rx: Receiver<Msg>) -> Result<()> {
        let exchange = KeyExchange::init();
        tx.send(Either::Left(exchange.public_key))?;
        let server_public = rx.recv()?.left().unwrap();
        let shared_secret = exchange.into_shared_secret(&server_public);

        let encrypted_key = rx.recv()?.right().unwrap();
        let (csc_id, decrypted_key) = decrypt_key(&shared_secret, &encrypted_key)?;

        assert_eq!(decrypted_key, SOME_KEY);
        assert_eq!(csc_id, CSC_ID);

        Ok(())
    }

    fn server(tx: Sender<Msg>, rx: Receiver<Msg>) -> Result<()> {
        let exchange = KeyExchange::init();
        let client_public = rx.recv()?.left().unwrap();
        tx.send(Either::Left(exchange.public_key))?;
        let shared_secret = exchange.into_shared_secret(&client_public);

        let encrypted_key = encrypt_key(&shared_secret, CSC_ID, SOME_KEY)?;
        tx.send(Either::Right(encrypted_key))?;

        Ok(())
    }

    #[test]
    fn full_exchange() {
        let (to_server, from_client) = channel();
        let (to_client, from_server) = channel();

        let client =
            thread::spawn(move || client(to_server, from_server).map_err(|e| e.to_string()));

        let server =
            thread::spawn(move || server(to_client, from_client).map_err(|e| e.to_string()));

        client.join().unwrap().unwrap();
        server.join().unwrap().unwrap();
    }

    fn some_shared_secret() -> SharedSecret {
        let exchange = KeyExchange::init();
        let pubk = exchange.public_key.clone();
        exchange.into_shared_secret(&pubk)
    }

    #[test]
    fn invalid_size_err() {
        let e = decrypt_key(&some_shared_secret(), "cGFzc3dvcmQ=")
            .err()
            .unwrap();
        assert!(matches!(e, Error::InvalidSize { got: 8 }));
    }
}
