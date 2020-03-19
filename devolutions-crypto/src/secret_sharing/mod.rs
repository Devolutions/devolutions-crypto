mod secret_sharing_v1;

use super::DataType;
use super::Error;
use super::Header;
use super::Result;
pub use super::SecretSharingVersion;
use super::ShareSubtype;

use secret_sharing_v1::ShareV1;

use std::convert::TryFrom;

#[derive(Clone)]
pub struct Share {
    pub(crate) header: Header<ShareSubtype, SecretSharingVersion>,
    payload: SharePayload,
}

#[derive(Clone)]
enum SharePayload {
    V1(ShareV1),
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
/// use devolutions_crypto::secret_sharing::{ generate_shared_key, SecretSharingVersion };
/// let shares = generate_shared_key(5, 3, 32, SecretSharingVersion::Latest).unwrap();
/// ```
pub fn generate_shared_key(
    n_shares: u8,
    threshold: u8,
    length: usize,
    version: SecretSharingVersion,
) -> Result<Vec<Share>> {
    let mut header = Header::default();

    header.data_type = DataType::Share;

    match version {
        SecretSharingVersion::V1 | SecretSharingVersion::Latest => {
            header.version = SecretSharingVersion::V1;

            let shares = ShareV1::generate_shared_key(n_shares, threshold, length)?;

            Ok(shares
                .map(|s| Share {
                    header: header.clone(),
                    payload: SharePayload::V1(s),
                })
                .collect())
        }
    }
}

/// Join multiple shares to regenerate a secret key.
///
/// # Arguments
///
/// * `shares` - The shares to join
///
/// # Example
/// ```
/// use devolutions_crypto::secret_sharing::{generate_shared_key, join_shares, SecretSharingVersion};
/// let shares = generate_shared_key(5, 3, 32, SecretSharingVersion::Latest).unwrap();
///
/// assert_eq!(shares.len(), 5);
///
/// let key = join_shares(&shares[2..5]).unwrap();
/// ```
pub fn join_shares<'a, I, J>(shares: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = &'a Share, IntoIter = J>,
    J: Iterator<Item = &'a Share> + Clone,
{
    let shares = shares.into_iter();

    let version = match shares.clone().peekable().peek() {
        Some(x) => x.header.version,
        None => return Err(Error::NotEnoughShares),
    };

    if !shares.clone().all(|share| match share.payload {
        SharePayload::V1(_) => version == SecretSharingVersion::V1,
    }) {
        return Err(Error::InconsistentVersion);
    }

    match version {
        SecretSharingVersion::V1 => {
            let shares = shares.map(|share| match &share.payload {
                SharePayload::V1(s) => s,
                //_ => unreachable!("This case should not happen because of previous check"),
            });

            ShareV1::join_shares(shares)
        }
        _ => Err(Error::UnknownVersion),
    }
}

impl From<Share> for Vec<u8> {
    /// Serialize the structure into a `Vec<u8>`, for storage, transmission or use in another language.
    fn from(data: Share) -> Self {
        let mut header: Self = data.header.into();
        let mut payload: Self = data.payload.into();
        header.append(&mut payload);
        header
    }
}

impl TryFrom<&[u8]> for Share {
    type Error = Error;

    /// Parses the data. Can return an Error of the data is invalid or unrecognized.
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < Header::len() {
            return Err(Error::InvalidLength);
        };

        let header = Header::try_from(&data[0..Header::len()])?;

        if header.data_type != DataType::Share {
            return Err(Error::InvalidDataType);
        }

        let payload = match SecretSharingVersion::try_from(header.version) {
            Ok(SecretSharingVersion::V1) => {
                SharePayload::V1(ShareV1::try_from(&data[Header::len()..])?)
            }
            _ => return Err(Error::UnknownVersion),
        };

        Ok(Self { header, payload })
    }
}

impl From<SharePayload> for Vec<u8> {
    fn from(data: SharePayload) -> Self {
        match data {
            SharePayload::V1(x) => x.into(),
        }
    }
}

#[test]
fn secret_sharing_test() {
    let shares = generate_shared_key(5, 3, 32, SecretSharingVersion::Latest).unwrap();

    assert_eq!(shares.len(), 5);

    let key1 = join_shares(&shares[0..3]).unwrap();
    let key2 = join_shares(&shares[2..5]).unwrap();
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
    assert!(join_shares(&shares[2..4]).is_err());
}
