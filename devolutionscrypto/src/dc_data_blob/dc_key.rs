use super::DcHeader;

use super::Result;

const SYMMETRIC: u16 = 1;
const PUBLIC: u16 = 2;
const PRIVATE: u16 = 3;

pub enum DcKey {
    Symmetric(Vec<u8>),
    Public(Vec<u8>),
    Private(Vec<u8>),
}

impl Drop for DcKey {
    fn drop(&mut self) {
        let data = match self {
            DcKey::Symmetric(x) => x.as_mut_slice(),
            DcKey::Public(x) => x.as_mut_slice(),
            DcKey::Private(x) => x.as_mut_slice(),
        };

        for b in data {
            *b = 0;
        }
    }
}

impl Into<Vec<u8>> for DcKey {
    fn into(mut self) -> Vec<u8> {
        let mut result = Vec::new();
        let data_ref = match self {
            DcKey::Symmetric(ref mut x) => x,
            DcKey::Public(ref mut x) => x,
            DcKey::Private(ref mut x) => x,
        };

        result.append(data_ref);
        result
    }
}

impl DcKey {
    pub fn try_from_header(data: &[u8], header: &DcHeader) -> Result<DcKey> {
        let data = Vec::from(data);
        let key = match header.data_subtype {
            SYMMETRIC => DcKey::Symmetric(data),
            PUBLIC => DcKey::Public(data),
            PRIVATE => DcKey::Private(data),
            _ => panic!(),
        };
        Ok(key)
    }

    pub fn key_type(&self) -> u16 {
        match self {
            DcKey::Symmetric(_) => SYMMETRIC,
            DcKey::Public(_) => PUBLIC,
            DcKey::Private(_) => PRIVATE,
        }
    }
}
