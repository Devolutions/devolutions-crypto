mod header;
mod payload;

mod ciphertext;
mod hash;
mod key;
mod shared_secret;

use super::DevoCryptoError;
use super::Result;

use self::ciphertext::{DcCiphertext, CIPHERTEXT};
use self::hash::{DcHash, HASH};
use self::key::{DcKey, KEY};
use self::shared_secret::{DcSharedSecret, SHARED_SECRET};

use self::header::DcHeader;
use self::payload::DcPayload;

use std;
use std::convert::TryFrom;

/// Data structure containing cryptographic information. It is made to be used as a black box
///     for misuse resistance. It implements `TryFrom<&[u8]` and `Into<Vec<u8>>` to be serialized
///     and parsed into raw bytes for use with other language and to send over a channel.
/// If the channel does not support raw byte, the data can be encoded easily using base64.
pub struct DcDataBlob {
    header: DcHeader,
    payload: DcPayload,
}

impl TryFrom<&[u8]> for DcDataBlob {
    type Error = DevoCryptoError;
    /// Parses the data. Can return an Error of the data is invalid or unrecognized.
    fn try_from(data: &[u8]) -> Result<DcDataBlob> {
        if data.len() < DcHeader::len() {
            return Err(DevoCryptoError::InvalidLength);
        };

        let header = DcHeader::try_from(&data[0..DcHeader::len()])?;
        let payload = DcPayload::try_from_header(&data[DcHeader::len()..], &header)?;
        Ok(DcDataBlob { header, payload })
    }
}

impl From<DcDataBlob> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(blob: DcDataBlob) -> Vec<u8> {
        let mut data: Vec<u8> = blob.header.into();
        let mut payload: Vec<u8> = blob.payload.into();
        data.append(&mut payload);
        data
    }
}

impl DcDataBlob {
    /// Creates an encrypted data blob from cleartext data and a key.
    /// # Arguments
    ///  * `data` - Data to encrypt.
    ///  * `key` - Key to use. Can be of arbitrary size.
    ///  * `version` - Version of the library to encrypt with. Use 0 for default.
    /// # Returns
    /// Returns a `DcDataBlob` containing the encrypted data.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::DcDataBlob;
    ///
    /// let data = b"somesecretdata";
    /// let key = b"somesecretkey";
    ///
    /// let encrypted_data = DcDataBlob::encrypt(data, key, None).unwrap();
    /// ```
    pub fn encrypt(data: &[u8], key: &[u8], version: Option<u16>) -> Result<DcDataBlob> {
        let mut header = DcHeader::new();
        let payload = DcPayload::encrypt(data, key, &mut header, version)?;
        Ok(DcDataBlob { header, payload })
    }

    /// Decrypt the data blob using a key.
    /// # Arguments
    ///  * `key` - Key to use. Can be of arbitrary size.
    /// # Returns
    /// Returns the decrypted data.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::DcDataBlob;
    ///
    /// let data = b"somesecretdata";
    /// let key = b"somesecretkey";
    ///
    /// let encrypted_data = DcDataBlob::encrypt(data, key, None).unwrap();
    /// let decrypted_data = encrypted_data.decrypt(key).unwrap();
    ///
    /// assert_eq!(data.to_vec(), decrypted_data);
    ///```
    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>> {
        self.payload.decrypt(key, &self.header)
    }

    /// Creates a data blob containing a password hash.
    /// # Arguments
    ///  * `password` - The password to hash.
    ///  * `iterations` - The number of iterations of the password hash.
    ///                     A higher number is slower but harder to brute-force.
    ///                     The recommended is 10000, but the number can be set by the user.
    /// # Returns
    /// Returns a `DcDataBlob` containing the hashed password.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::DcDataBlob;
    ///
    /// let password = b"somesuperstrongpa$$w0rd!";
    ///
    /// let hashed_password = DcDataBlob::hash_password(password, 10000);
    /// ```
    pub fn hash_password(password: &[u8], iterations: u32) -> Result<DcDataBlob> {
        let mut header = DcHeader::new();
        let payload = DcPayload::hash_password(password, iterations, &mut header)?;
        Ok(DcDataBlob { header, payload })
    }

    /// Verify if the blob matches with the specified password. Should execute in constant time.
    /// # Arguments
    ///  * `password` - Password to verify.
    /// # Returns
    /// Returns true if the password matches and false if it doesn't.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::DcDataBlob;
    ///
    /// let password = b"somesuperstrongpa$$w0rd!";
    ///
    /// let hashed_password = DcDataBlob::hash_password(password, 10000).unwrap();
    /// assert!(hashed_password.verify_password(b"somesuperstrongpa$$w0rd!").unwrap());
    /// assert!(!hashed_password.verify_password(b"someweakpa$$w0rd!").unwrap());
    /// ```
    pub fn verify_password(&self, password: &[u8]) -> Result<bool> {
        self.payload.verify_password(password)
    }

    /// Generates a key pair to use in a key exchange. See `mix_key_exchange` for a complete usage.
    /// # Returns
    /// Returns, in order, the private key and the public key in a `DcDataBlob`.
    /// # Example
    /// ```rust
    /// use devolutions_crypto::DcDataBlob;
    ///
    /// let (private, public) = DcDataBlob::generate_key_exchange().unwrap();
    /// ```
    pub fn generate_key_exchange() -> Result<(DcDataBlob, DcDataBlob)> {
        let mut header_private = DcHeader::new();
        let mut header_public = DcHeader::new();
        let (payload_private, payload_public) =
            DcPayload::generate_key_exchange(&mut header_private, &mut header_public)?;
        Ok((
            DcDataBlob {
                header: header_private,
                payload: payload_private,
            },
            DcDataBlob {
                header: header_public,
                payload: payload_public,
            },
        ))
    }

    /// Mix a private key with another client public key to get a shared secret.
    /// # Arguments
    ///  * `self` - The user's private key obtained through `generate_key_exchange`.
    ///  * `public` - The peer public key.
    /// # Returns
    /// Returns a shared secret in the form of a `Vec<u8>`, which can then be used
    ///     as an encryption key between the two peers.
    /// # Example
    /// ```rust
    /// use std::convert::TryFrom as _;
    /// use devolutions_crypto::DcDataBlob;
    /// # fn send_key_to_alice(_: &[u8]) {}
    /// # fn send_key_to_bob(_: &[u8]) {}
    /// # fn receive_key_from_alice() {}
    /// # fn receive_key_from_bob() {}
    ///
    /// // This happens on Bob's side.
    /// let (bob_priv, bob_pub) = DcDataBlob::generate_key_exchange().unwrap();
    /// let bob_serialized_pub: Vec<u8> = bob_pub.into();
    ///
    /// send_key_to_alice(&bob_serialized_pub);
    ///
    /// // This happens on Alice's side.
    /// let (alice_priv, alice_pub) = DcDataBlob::generate_key_exchange().unwrap();
    /// let alice_serialized_pub: Vec<u8> = alice_pub.into();
    ///
    /// send_key_to_bob(&alice_serialized_pub);
    ///
    /// // Bob can now generate the shared secret.
    /// let alice_received_serialized_pub = receive_key_from_alice();
    /// # let alice_received_serialized_pub = alice_serialized_pub;
    /// let alice_received_pub = DcDataBlob::try_from(alice_received_serialized_pub.as_slice()).unwrap();
    ///
    /// let bob_shared = bob_priv.mix_key_exchange(alice_received_pub).unwrap();
    ///
    /// // Alice can now generate the shared secret
    /// let bob_received_serialized_pub = receive_key_from_bob();
    /// # let bob_received_serialized_pub = bob_serialized_pub;
    /// let bob_received_pub = DcDataBlob::try_from(bob_received_serialized_pub.as_slice()).unwrap();
    ///
    /// let alice_shared = alice_priv.mix_key_exchange(bob_received_pub).unwrap();
    ///
    /// // They now have a shared secret!
    /// assert_eq!(bob_shared, alice_shared);
    /// ```
    pub fn mix_key_exchange(self, public: DcDataBlob) -> Result<Vec<u8>> {
        self.payload.mix_key_exchange(public.payload)
    }

    /// Generate a key and split it in `n` shares use. You will need `threshold` shares to recover the key.
    ///
    /// # Arguments
    ///
    /// * `n_shares` - Number of shares to generate
    /// * `threshold` - The number of shares needed to recover the key
    /// * `length` - The desired length of the key to generate
    ///
    /// # Example
    /// ```
    /// use devolutions_crypto::DcDataBlob;
    /// let shares = DcDataBlob::generate_shared_key(5, 3, 32).unwrap();
    ///
    /// assert_eq!(shares.len(), 5);
    ///
    /// let key = DcDataBlob::join_shares(&shares[2..5]).unwrap();
    /// ```
    pub fn generate_shared_key(
        n_shares: u8,
        threshold: u8,
        length: usize,
    ) -> Result<Vec<DcDataBlob>> {
        let mut header = DcHeader::new();
        Ok(
            DcPayload::generate_shared_key(n_shares, threshold, length, &mut header)?
                .map(move |s| DcDataBlob {
                    header: header.clone(),
                    payload: s,
                })
                .collect(),
        )
    }

    /// Join multiple shares to regenerate a secret key.
    ///
    /// # Arguments
    ///
    /// * `shares` - The shares to join
    ///
    /// # Example
    /// ```
    /// use devolutions_crypto::DcDataBlob;
    /// let shares = DcDataBlob::generate_shared_key(5, 3, 32).unwrap();
    ///
    /// assert_eq!(shares.len(), 5);
    ///
    /// let key = DcDataBlob::join_shares(&shares[2..5]).unwrap();
    /// ```
    pub fn join_shares<'a, I, J>(shares: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = &'a DcDataBlob, IntoIter = J>,
        J: Iterator<Item = &'a DcDataBlob> + Clone,
    {
        let shares = shares.into_iter().map(move |s| &s.payload);
        DcPayload::join_shares(shares)
    }
}

#[test]
fn encrypt_decrypt_test() {
    let key = "0123456789abcdefghijkl".as_bytes();
    let data = "This is a very complex string of character that we need to encrypt".as_bytes();

    let encrypted = DcDataBlob::encrypt(data, &key, None).unwrap();
    let encrypted: Vec<u8> = encrypted.into();

    let encrypted = DcDataBlob::try_from(encrypted.as_slice()).unwrap();
    let decrypted = encrypted.decrypt(key).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn encrypt_v1_test() {
    use base64;

    let data = "testdata".as_bytes();
    let key = base64::decode("Sr98VxTc424QFZDH2csZni/n5tKk2/d4ow7iGUqd5HQ=").unwrap();

    let encrypted = DcDataBlob::encrypt(data, &key, Some(1)).unwrap();

    assert_eq!(encrypted.header.version, 1);

    let encrypted: Vec<u8> = encrypted.into();

    let encrypted = DcDataBlob::try_from(encrypted.as_slice()).unwrap();
    let decrypted = encrypted.decrypt(&key).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn encrypt_v2_test() {
    use base64;

    let data = "testdata".as_bytes();
    let key = base64::decode("HOPWSC5oA9Az9SAnuwGI3nT3Dx/z2qtHBQI1k2WvVFo=").unwrap();

    let encrypted = DcDataBlob::encrypt(data, &key, Some(2)).unwrap();

    assert_eq!(encrypted.header.version, 2);

    let encrypted: Vec<u8> = encrypted.into();

    let encrypted = DcDataBlob::try_from(encrypted.as_slice()).unwrap();
    let decrypted = encrypted.decrypt(&key).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn decrypt_v1_test() {
    use base64;

    let data = base64::decode("DQwCAAAAAQBo87jumRMVMIuTP8cFbFTgwDguKXkBvlkE/rNu4HLRRueQqfCzmXEyGR7qWAKkz4BFFyGedCmQ/xXTW4V7UnV9um1TJClz3yzQy0SQui+1UA==").unwrap();
    let key = base64::decode("Xk63o/+6TeC63Z4j2HZOOdiGfqjQNJz1PTbQ3/L5nM0=").unwrap();
    let encrypted = DcDataBlob::try_from(data.as_slice()).unwrap();

    assert_eq!(encrypted.header.version, 1);

    let decrypted = encrypted.decrypt(&key).unwrap();

    assert_eq!(decrypted, "A secret v1 string".as_bytes());
}

#[test]
fn decrypt_v2_test() {
    use base64;

    let data = base64::decode(
        "DQwCAAAAAgCcJ6yg2jWt3Zr1ZvenW4/AFi3Xj82IqfvaHmmPzMgzkrTfeKp8Shey3KLLLOhtMU4eNmYBRcAtSPfQ",
    )
    .unwrap();
    let key = base64::decode("Dipney+DR14k+Bvz/gBJrM19yAerG/0g5iHSm/HcOJU=").unwrap();
    let encrypted = DcDataBlob::try_from(data.as_slice()).unwrap();

    assert_eq!(encrypted.header.version, 2);

    let decrypted = encrypted.decrypt(&key).unwrap();

    assert_eq!(decrypted, "A secret v2 string".as_bytes());
}

#[test]
fn password_test() {
    let pass = "thisisaveryveryverystrongPa$$w0rd , //".as_bytes();
    let iterations = 1234u32;

    let hash = DcDataBlob::hash_password(pass, iterations).unwrap();

    assert!(hash.verify_password(pass).unwrap());
    assert!(!hash.verify_password("averybadpassword".as_bytes()).unwrap())
}

#[test]
fn ecdh_test() {
    let (bob_priv, bob_pub) = DcDataBlob::generate_key_exchange().unwrap();
    let (alice_priv, alice_pub) = DcDataBlob::generate_key_exchange().unwrap();

    let bob_shared = bob_priv.mix_key_exchange(alice_pub).unwrap();
    let alice_shared = alice_priv.mix_key_exchange(bob_pub).unwrap();

    assert_eq!(bob_shared, alice_shared);
}

#[test]
fn secret_sharing_test() {
    let shares = DcDataBlob::generate_shared_key(5, 3, 32).unwrap();

    assert_eq!(shares.len(), 5);

    let key1 = DcDataBlob::join_shares(&shares[0..3]).unwrap();
    let key2 = DcDataBlob::join_shares(&shares[2..5]).unwrap();
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
    assert!(DcDataBlob::join_shares(&shares[2..4]).is_err());
}
