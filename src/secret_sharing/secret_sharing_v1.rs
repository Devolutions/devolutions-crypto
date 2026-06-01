//! Secret Sharing V1: Shamir's Secret Sharing
use super::Error;
use super::Result;

use std::convert::TryFrom;

use blahaj::{Share, Sharks};
use zeroize::Zeroizing;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

// This will need some work in the Sharks crate to get the zeroize working.
//#[derive(Zeroize)]
//#[zeroize(drop)]
#[derive(Clone)]
pub struct ShareV1 {
    threshold: u8,
    share: Share,
}

// `blahaj::Share` only implements `arbitrary` 0.4's `Arbitrary`, so it can't be
// derived under `arbitrary` 1.x. Build the share from raw bytes instead, the same
// way `TryFrom<&[u8]>` does, to avoid depending on `blahaj::Share: Arbitrary`.
#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for ShareV1 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let threshold = u8::arbitrary(u)?;
        let bytes = <Vec<u8>>::arbitrary(u)?;
        let share = Share::try_from(bytes.as_slice()).map_err(|_| arbitrary::Error::IncorrectFormat)?;

        Ok(ShareV1 { threshold, share })
    }
}

impl core::fmt::Debug for ShareV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> std::result::Result<(), core::fmt::Error> {
        write!(f, "Share with threshold {}", self.threshold)
    }
}

impl From<ShareV1> for Vec<u8> {
    fn from(share: ShareV1) -> Vec<u8> {
        let mut data: Vec<u8> = vec![share.threshold];
        data.append(&mut (&share.share).into());

        data
    }
}

impl TryFrom<&[u8]> for ShareV1 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<ShareV1> {
        if data.len() < 3 {
            return Err(Error::InvalidLength);
        };

        let threshold = data[0];

        let share = match Share::try_from(&data[1..]) {
            Ok(s) => s,
            Err(_) => return Err(Error::InvalidData),
        };

        Ok(ShareV1 { threshold, share })
    }
}

impl ShareV1 {
    pub fn generate_shared_key(
        n_shares: u8,
        threshold: u8,
        length: usize,
    ) -> Result<impl Iterator<Item = ShareV1>> {
        if n_shares < threshold {
            return Err(Error::NotEnoughShares);
        }

        let secret = Zeroizing::new(crate::utils::generate_key(length)?);
        let sharks = Sharks(threshold);
        let dealer = sharks.dealer_rng(&secret, &mut rand_08::rngs::OsRng);

        Ok(dealer.take(n_shares as usize).map(move |s| ShareV1 {
            threshold,
            share: s,
        }))
    }

    pub fn join_shares<'a, I, J>(shares: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = &'a ShareV1, IntoIter = J>,
        J: Iterator<Item = &'a ShareV1> + Clone,
    {
        let shares = shares.into_iter();
        let threshold = match shares.clone().peekable().peek() {
            Some(x) => x.threshold,
            None => return Err(Error::NotEnoughShares),
        };

        let sharks = Sharks(threshold);

        let shares = shares.map(|s| &s.share);
        match sharks.recover(shares) {
            Ok(x) => Ok(x),
            Err(_) => Err(Error::NotEnoughShares),
        }
    }
}
