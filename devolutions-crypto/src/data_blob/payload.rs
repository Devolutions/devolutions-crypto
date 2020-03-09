use std::convert::TryFrom;

use crate::DcDataBlob;

use super::DevoCryptoError;
use super::Result;

use super::Argon2Parameters;
use super::DcHeader;

use super::{DcCiphertext, CIPHERTEXT};
use super::{DcHash, HASH};
use super::{DcKey, KEY};
use super::{DcSharedSecret, SHARED_SECRET};

pub enum DcPayload {
    Key(DcKey),
    Ciphertext(DcCiphertext),
    SharedSecret(DcSharedSecret),
    Hash(DcHash),
}

impl DcPayload {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcPayload> {
        match header.data_type {
            KEY => Ok(DcPayload::Key(DcKey::try_from_header(data, header)?)),
            CIPHERTEXT => Ok(DcPayload::Ciphertext(DcCiphertext::try_from_header(
                data, header,
            )?)),
            SHARED_SECRET => Ok(DcPayload::SharedSecret(DcSharedSecret::try_from_header(
                data, header,
            )?)),
            HASH => Ok(DcPayload::Hash(DcHash::try_from_header(data, header)?)),
            _ => Err(DevoCryptoError::UnknownType),
        }
    }

    pub fn encrypt(
        data: &[u8],
        key: &[u8],
        header: &mut DcHeader,
        version: Option<u16>,
    ) -> Result<DcPayload> {
        Ok(DcPayload::Ciphertext(DcCiphertext::encrypt(
            data, key, header, version,
        )?))
    }

    pub fn encrypt_asymmetric(
        data: &[u8],
        public_key: &DcDataBlob,
        header: &mut DcHeader,
        version: Option<u16>,
    ) -> Result<DcPayload> {
        Ok(DcPayload::Ciphertext(DcCiphertext::encrypt_asymmetric(
            data, public_key, header, version,
        )?))
    }

    pub fn decrypt(&self, key: &[u8], header: &DcHeader) -> Result<Vec<u8>> {
        match self {
            DcPayload::Ciphertext(x) => x.decrypt(key, header),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }

    pub fn decrypt_asymmetric(
        &self,
        private_key: &DcDataBlob,
        header: &DcHeader,
    ) -> Result<Vec<u8>> {
        match self {
            DcPayload::Ciphertext(x) => x.decrypt_asymmetric(private_key, header),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }

    pub fn hash_password(pass: &[u8], iterations: u32, header: &mut DcHeader) -> Result<DcPayload> {
        Ok(DcPayload::Hash(DcHash::hash_password(
            pass, iterations, header,
        )?))
    }

    pub fn verify_password(&self, pass: &[u8]) -> Result<bool> {
        match self {
            DcPayload::Hash(x) => x.verify_password(pass),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }

    pub fn generate_key_exchange(
        header_private: &mut DcHeader,
        header_public: &mut DcHeader,
    ) -> Result<(DcPayload, DcPayload)> {
        let (private_key, public_key) =
            DcKey::generate_key_exchange(header_private, header_public)?;
        Ok((DcPayload::Key(private_key), DcPayload::Key(public_key)))
    }

    pub fn mix_key_exchange(self, public: DcPayload) -> Result<Vec<u8>> {
        match (self, public) {
            (DcPayload::Key(private), DcPayload::Key(public)) => private.mix_key_exchange(public),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }

    pub fn generate_shared_key(
        n_shares: u8,
        threshold: u8,
        length: usize,
        header: &mut DcHeader,
    ) -> Result<impl Iterator<Item = DcPayload>> {
        let shares = DcSharedSecret::generate_shared_key(n_shares, threshold, length, header)?;
        let shares = shares.map(DcPayload::SharedSecret);
        Ok(shares)
    }

    pub fn join_shares<'a, I, J>(shares: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = &'a DcPayload, IntoIter = J>,
        J: Iterator<Item = &'a DcPayload> + Clone,
    {
        let shares = shares.into_iter();

        if !shares.clone().all(|share| match share {
            DcPayload::SharedSecret(_) => true,
            _ => false,
        }) {
            return Err(DevoCryptoError::InvalidDataType);
        }

        let shares = shares.map(move |share| match share {
            DcPayload::SharedSecret(s) => s,
            _ => unreachable!("This case should not happen because of previous check"),
        });

        DcSharedSecret::join_shares(shares)
    }

    pub fn derive_keypair(
        password: &[u8],
        parameters: &Argon2Parameters,
        private_header: &mut DcHeader,
        public_header: &mut DcHeader,
    ) -> Result<(DcPayload, DcPayload)> {
        let (private, public) =
            DcKey::derive_keypair(password, parameters, private_header, public_header)?;
        Ok((DcPayload::Key(private), DcPayload::Key(public)))
    }
}

impl TryFrom<&DcPayload> for x25519_dalek::PublicKey {
    type Error = DevoCryptoError;

    fn try_from(data: &DcPayload) -> Result<Self> {
        match data {
            DcPayload::Key(x) => Self::try_from(x),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }
}

impl TryFrom<&DcPayload> for x25519_dalek::StaticSecret {
    type Error = DevoCryptoError;

    fn try_from(data: &DcPayload) -> Result<Self> {
        match data {
            DcPayload::Key(x) => Self::try_from(x),
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }
}

impl From<DcPayload> for Vec<u8> {
    fn from(payload: DcPayload) -> Vec<u8> {
        match payload {
            DcPayload::Key(x) => x.into(),
            DcPayload::Ciphertext(x) => x.into(),
            DcPayload::SharedSecret(x) => x.into(),
            DcPayload::Hash(x) => x.into(),
        }
    }
}
