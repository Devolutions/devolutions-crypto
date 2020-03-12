use super::DevoCryptoError;
use super::Result;

use std::convert::TryFrom;

use sharks::{Share, Sharks};
use zeroize::Zeroize;

// This will need some work in the Sharks crate to get the zeroize working.
//#[derive(Zeroize)]
//#[zeroize(drop)]
#[derive(Clone)]
pub struct DcSharedSecretV1 {
    threshold: u8,
    share: Share,
}

impl From<DcSharedSecretV1> for Vec<u8> {
    fn from(share: DcSharedSecretV1) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();

        data.push(share.threshold);
        data.append(&mut (&share.share).into());

        data
    }
}

impl TryFrom<&[u8]> for DcSharedSecretV1 {
    type Error = DevoCryptoError;

    fn try_from(data: &[u8]) -> Result<DcSharedSecretV1> {
        if data.len() < 3 {
            return Err(DevoCryptoError::InvalidLength);
        };

        let threshold = data[0];
        let share = Share::from(&data[1..]);

        Ok(DcSharedSecretV1 { threshold, share })
    }
}

impl DcSharedSecretV1 {
    pub fn generate_shared_key(
        n_shares: u8,
        threshold: u8,
        length: usize,
    ) -> Result<impl Iterator<Item = DcSharedSecretV1>> {
        if n_shares < threshold {
            return Err(DevoCryptoError::NotEnoughShares);
        }

        let mut secret = crate::utils::generate_key(length);
        let sharks = Sharks(threshold);
        let dealer = sharks.dealer(&secret);

        secret.zeroize();

        Ok(dealer
            .take(n_shares as usize)
            .map(move |s| DcSharedSecretV1 {
                threshold,
                share: s,
            }))
    }

    pub fn join_shares<'a, I, J>(shares: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = &'a DcSharedSecretV1, IntoIter = J>,
        J: Iterator<Item = &'a DcSharedSecretV1> + Clone,
    {
        let shares = shares.into_iter();
        let threshold = shares
            .clone()
            .peekable()
            .peek()
            .expect("Should have at least one share")
            .threshold;
        let sharks = Sharks(threshold);

        let shares = shares.map(|s| &s.share);
        match sharks.recover(shares) {
            Ok(x) => Ok(x),
            Err(_) => Err(DevoCryptoError::NotEnoughShares),
        }
    }
}
