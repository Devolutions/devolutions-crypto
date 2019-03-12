use super::DcHeader;
use super::DevoCryptoError;
use super::Result;

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

const PRIVATE: u16 = 1;
const PUBLIC: u16 = 2;

pub enum DcKeyV1 {
    Private(StaticSecret),
    Public(PublicKey),
}

impl Into<Vec<u8>> for DcKeyV1 {
    fn into(self) -> Vec<u8> {
        match self {
            DcKeyV1::Private(x) => x.to_bytes().to_vec(),
            DcKeyV1::Public(x) => x.as_bytes().to_vec(),
        }
    }
}

impl DcKeyV1 {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcKeyV1> {
        if data.len() != 32 {
            return Err(DevoCryptoError::InvalidLength);
        };

        let mut key_bytes = [0u8; 32];

        key_bytes.copy_from_slice(&data[0..32]);

        let key = match header.data_subtype {
            PRIVATE => DcKeyV1::Private(StaticSecret::from(key_bytes)),
            PUBLIC => DcKeyV1::Public(PublicKey::from(key_bytes)),
            _ => return Err(DevoCryptoError::UnknownSubtype),
        };
        Ok(key)
    }

    pub fn generate_key_exchange(
        private_header: &mut DcHeader,
        public_header: &mut DcHeader,
    ) -> Result<(DcKeyV1, DcKeyV1)> {
        private_header.data_subtype = PRIVATE;
        public_header.data_subtype = PUBLIC;

        let mut rng = OsRng::new()?;

        let private = StaticSecret::new(&mut rng);
        let public = PublicKey::from(&private);

        Ok((DcKeyV1::Private(private), DcKeyV1::Public(public)))
    }

    pub fn mix_key_exchange(self, public: DcKeyV1) -> Result<Vec<u8>> {
        match (self, public) {
            (DcKeyV1::Private(private), DcKeyV1::Public(public)) => {
                Ok(private.diffie_hellman(&public).as_bytes().to_vec())
            }
            _ => Err(DevoCryptoError::InvalidDataType),
        }
    }
}
