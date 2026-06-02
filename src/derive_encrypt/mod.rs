mod kdf_encrypted_data_v1;

use std::borrow::Borrow;
use std::convert::TryFrom;

use crate::ciphertext;
use crate::enums::KdfEncryptedDataSubtype;
use crate::key_derivation::DerivationParameters;
use crate::{
    CiphertextVersion, DataType, Error, Header, HeaderType, KdfEncryptedDataVersion, Result,
};

use kdf_encrypted_data_v1::KdfEncryptedDataV1;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

/// A blob that stores key derivation parameters alongside a symmetric ciphertext,
/// allowing decryption with only the original password.
///
/// The serialized format contains the [`DerivationParameters`](crate::key_derivation::DerivationParameters)
/// used to derive the key and the resulting [`Ciphertext`](crate::ciphertext::Ciphertext),
/// so no external state is required to decrypt.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct KdfEncryptedData {
    pub(crate) header: Header<KdfEncryptedData>,
    payload: KdfEncryptedDataPayload,
}

impl HeaderType for KdfEncryptedData {
    type Version = KdfEncryptedDataVersion;
    type Subtype = KdfEncryptedDataSubtype;

    fn data_type() -> DataType {
        DataType::KdfEncryptedData
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
enum KdfEncryptedDataPayload {
    V1(KdfEncryptedDataV1),
}

/// Encrypts `data` with a key derived from `password` and returns a self-contained blob.
///
/// Equivalent to calling [`encrypt_with_password_and_aad`] with an empty AAD.
///
/// # Arguments
///  * `data` - The plaintext data to encrypt.
///  * `password` - The password from which the encryption key is derived.
///  * `derivation_parameters` - Pre-built key derivation parameters (includes the salt). Use
///    [`Argon2::new().derive(password)`](crate::key_derivation::Argon2::derive) to generate them.
///  * `ciphertext_version` - Cipher to use. `CiphertextVersion::Latest` is recommended.
/// # Returns
/// Returns a [`KdfEncryptedData`] blob containing the key derivation parameters and the ciphertext.
/// # Example
/// ```rust
/// use devolutions_crypto::derive_encrypt::encrypt_with_password;
/// use devolutions_crypto::key_derivation::Argon2;
/// use devolutions_crypto::CiphertextVersion;
///
/// let params = Argon2::new().parameters();
/// let blob = encrypt_with_password(b"secret", b"password", params, CiphertextVersion::Latest).unwrap();
/// let plaintext = blob.decrypt_with_password(b"password").unwrap();
/// assert_eq!(plaintext, b"secret");
/// ```
pub fn encrypt_with_password(
    data: &[u8],
    password: &[u8],
    derivation_parameters: DerivationParameters,
    ciphertext_version: CiphertextVersion,
) -> Result<KdfEncryptedData> {
    encrypt_with_password_and_aad(
        data,
        password,
        [].as_slice(),
        derivation_parameters,
        ciphertext_version,
    )
}

/// Encrypts `data` with a key derived from `password` and authenticates `aad`.
///
/// # Arguments
///  * `data` - The plaintext data to encrypt.
///  * `password` - The password from which the encryption key is derived.
///  * `aad` - Additional Authenticated Data bound to the ciphertext; must be provided unchanged on decryption.
///  * `derivation_parameters` - Pre-built key derivation parameters (includes the salt). Use
///    [`Argon2::new().derive(password)`](crate::key_derivation::Argon2::derive) to generate them.
///  * `ciphertext_version` - Cipher to use. `CiphertextVersion::Latest` is recommended.
/// # Returns
/// Returns a [`KdfEncryptedData`] blob containing the key derivation parameters and the ciphertext.
pub fn encrypt_with_password_and_aad(
    data: &[u8],
    password: &[u8],
    aad: &[u8],
    derivation_parameters: DerivationParameters,
    ciphertext_version: CiphertextVersion,
) -> Result<KdfEncryptedData> {
    let mut header: Header<KdfEncryptedData> = Header::default();
    header.version = KdfEncryptedDataVersion::V1;

    let secret_key = derivation_parameters.derive(password)?;
    let ciphertext =
        ciphertext::encrypt_with_secret_key_and_aad(data, &secret_key, aad, ciphertext_version)?;

    Ok(KdfEncryptedData {
        header,
        payload: KdfEncryptedDataPayload::V1(KdfEncryptedDataV1 {
            derivation_parameters,
            ciphertext,
        }),
    })
}

impl KdfEncryptedData {
    /// Decrypts this blob using `password`.
    ///
    /// Equivalent to calling [`decrypt_with_password_and_aad`](Self::decrypt_with_password_and_aad) with an empty AAD.
    ///
    /// # Arguments
    ///  * `password` - The password used during encryption.
    /// # Returns
    /// Returns the decrypted plaintext, or an error if the password is wrong or the blob is invalid.
    pub fn decrypt_with_password(&self, password: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_password_and_aad(password, [].as_slice())
    }

    /// Decrypts this blob using `password`, verifying `aad`.
    ///
    /// # Arguments
    ///  * `password` - The password used during encryption.
    ///  * `aad` - The same Additional Authenticated Data that was provided during encryption.
    /// # Returns
    /// Returns the decrypted plaintext, or an error if the password is wrong, the AAD does not match,
    /// or the blob is invalid.
    pub fn decrypt_with_password_and_aad(&self, password: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match &self.payload {
            KdfEncryptedDataPayload::V1(payload) => {
                let secret_key = payload.derivation_parameters.derive(password)?;
                payload
                    .ciphertext
                    .decrypt_with_secret_key_and_aad(&secret_key, aad)
            }
        }
    }
}

impl From<KdfEncryptedData> for Vec<u8> {
    fn from(data: KdfEncryptedData) -> Self {
        let mut header: Self = data.header.borrow().into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl From<KdfEncryptedDataPayload> for Vec<u8> {
    fn from(data: KdfEncryptedDataPayload) -> Self {
        match data {
            KdfEncryptedDataPayload::V1(v1) => v1.borrow().into(),
        }
    }
}

impl TryFrom<&[u8]> for KdfEncryptedData {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        }

        let header = Header::try_from(&data[0..Header::len()])?;

        let payload = match header.version {
            KdfEncryptedDataVersion::V1 => {
                KdfEncryptedDataPayload::V1(KdfEncryptedDataV1::try_from(&data[Header::len()..])?)
            }
            // `Latest` (discriminant 0) is a dispatch sentinel for the encrypt path only;
            // it is never written to the wire. Blobs on disk always carry a concrete version.
            KdfEncryptedDataVersion::Latest => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use crate::key_derivation::Argon2;
    use crate::utils::validate_header;
    use crate::Pbkdf2;

    use super::*;

    #[test]
    fn derive_encrypt_roundtrip_latest() {
        let data = b"derive encrypt payload";
        let password = b"a very strong password";
        let aad = b"public data";

        let params = Argon2::new().parameters();
        let wrapped =
            encrypt_with_password_and_aad(data, password, aad, params, CiphertextVersion::Latest)
                .unwrap();

        let wrapped_raw: Vec<u8> = wrapped.into();
        let wrapped = KdfEncryptedData::try_from(wrapped_raw.as_slice()).unwrap();
        let decrypted = wrapped
            .decrypt_with_password_and_aad(password, aad)
            .unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn derive_encrypt_pbkdf2() {
        let data = b"derive encrypt payload";
        let password = b"a very strong password";

        let params = Pbkdf2::with_params(10).parameters().unwrap();
        let wrapped =
            encrypt_with_password(data, password, params, CiphertextVersion::Latest).unwrap();

        assert!(wrapped.decrypt_with_password(b"wrong password").is_err());
    }

    #[test]
    fn derive_encrypt_wrong_password_fails() {
        let data = b"derive encrypt payload";
        let password = b"a very strong password";

        let params = Argon2::new().parameters();
        let wrapped =
            encrypt_with_password(data, password, params, CiphertextVersion::Latest).unwrap();

        assert!(wrapped.decrypt_with_password(b"wrong password").is_err());
    }

    #[test]
    fn derive_encrypt_wrong_aad_fails() {
        let data = b"derive encrypt payload";
        let password = b"a very strong password";

        let params = Argon2::new().parameters();
        let wrapped = encrypt_with_password_and_aad(
            data,
            password,
            b"the right aad",
            params,
            CiphertextVersion::Latest,
        )
        .unwrap();

        assert!(wrapped
            .decrypt_with_password_and_aad(password, b"wrong aad")
            .is_err());
    }

    #[test]
    fn validate_header_accepts_derive_encrypt() {
        let password = b"a very strong password";
        let params = Argon2::new().parameters();
        let wrapped = encrypt_with_password(
            b"derive encrypt payload",
            password,
            params,
            CiphertextVersion::Latest,
        )
        .unwrap();

        let wrapped_raw: Vec<u8> = wrapped.into();
        assert!(validate_header(
            wrapped_raw.as_slice(),
            DataType::KdfEncryptedData
        ));
        assert!(!validate_header(
            wrapped_raw.as_slice(),
            DataType::Ciphertext
        ));
    }
}
