mod dc_key_v1;

use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use self::dc_key_v1::DcKeyV1;

pub const KEY: u16 = 1;

const V1: u16 = 1;

pub enum DcKey {
    V1(DcKeyV1),
}

impl DcKey {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcKey> {
        match header.version {
            V1 => Ok(DcKey::V1(DcKeyV1::try_from_header(data, header)?)),
            _ => Err(DevoCryptoError::UnknownVersion),
        }
    }

    pub fn generate_key_exchange(
        private_header: &mut DcHeader,
        public_header: &mut DcHeader,
    ) -> Result<(DcKey, DcKey)> {
        private_header.data_type = KEY;
        public_header.data_type = KEY;
        private_header.version = V1;
        public_header.version = V1;

        let (private_key, public_key) =
            DcKeyV1::generate_key_exchange(private_header, public_header)?;

        Ok((DcKey::V1(private_key), DcKey::V1(public_key)))
    }

    pub fn mix_key_exchange(self, public: DcKey) -> Result<Vec<u8>> {
        match (self, public) {
            (DcKey::V1(private), DcKey::V1(public)) => private.mix_key_exchange(public),
        }
    }
}

impl Into<Vec<u8>> for DcKey {
    fn into(self) -> Vec<u8> {
        match self {
            DcKey::V1(x) => x.into(),
        }
    }
}