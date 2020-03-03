mod shared_secret_v1;

use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use self::shared_secret_v1::DcSharedSecretV1;

use std::convert::TryFrom as _;

pub const SHARED_SECRET: u16 = 5;

const V1: u16 = 1;

pub enum DcSharedSecret {
    V1(DcSharedSecretV1),
}

impl DcSharedSecret {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcSharedSecret> {
        match header.version {
            V1 => Ok(DcSharedSecret::V1(DcSharedSecretV1::try_from(data)?)),
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }
}

impl From<DcSharedSecret> for Vec<u8> {
    fn from(share: DcSharedSecret) -> Vec<u8> {
        match share {
            DcSharedSecret::V1(x) => x.into(),
        }
    }
}

impl DcSharedSecret {
    pub fn generate_shared_key(
        n_shares: u8,
        threshold: u8,
        length: usize,
        header: &mut DcHeader,
    ) -> Result<impl Iterator<Item = DcSharedSecret>> {
        header.data_type = SHARED_SECRET;
        header.version = V1;

        Ok(
            DcSharedSecretV1::generate_shared_key(n_shares, threshold, length)?
                .map(|s| DcSharedSecret::V1(s)),
        )
    }

    pub fn join_shares<'a, I, J>(shares: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = &'a DcSharedSecret, IntoIter = J>,
        J: Iterator<Item = &'a DcSharedSecret> + Clone,
    {
        let shares = shares.into_iter();
        let version = match shares.clone().peekable().peek() {
            Some(&DcSharedSecret::V1(_)) => V1,
            None => return Err(DevoCryptoError::NotEnoughShares),
        };

        if !shares.clone().all(|share| match &share {
            &DcSharedSecret::V1(_) => version == V1,
        }) {
            return Err(DevoCryptoError::InconsistentVersion);
        }

        match version {
            V1 => {
                let shares = shares.map(|share| match share {
                    DcSharedSecret::V1(s) => s,
                    //_ => unreachable!("This case should not happen because of previous check"),
                });

                DcSharedSecretV1::join_shares(shares)
            }
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }
}
