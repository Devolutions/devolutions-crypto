use super::Error;
use super::Result;

use std::convert::TryFrom;
use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize;

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[derive(Zeroize, Clone, Debug)]
#[zeroize(drop)]
pub struct PasswordHashV1 {
    iterations: u32,
    salt: [u8; 32],
    hash: [u8; 32],
}

#[cfg(feature = "fuzz")]
impl Arbitrary for PasswordHashV1 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let salt: [u8; 32] = Arbitrary::arbitrary(u)?;
        let hash: [u8; 32] = Arbitrary::arbitrary(u)?;
        Ok(Self {
            iterations: 2,
            salt,
            hash,
        })
    }
}

impl From<PasswordHashV1> for Vec<u8> {
    fn from(hash: PasswordHashV1) -> Vec<u8> {
        let iterations = hash.iterations;
        let mut data = Vec::with_capacity(4);
        data.write_u32::<LittleEndian>(iterations).unwrap();

        data.extend_from_slice(&hash.salt);
        data.extend_from_slice(&hash.hash);

        data
    }
}

impl TryFrom<&[u8]> for PasswordHashV1 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<PasswordHashV1> {
        if data.len() != 68 {
            return Err(Error::InvalidLength);
        };

        let mut vec_iterations = Cursor::new(&data[0..4]);
        let mut salt = [0u8; 32];
        let mut hash = [0u8; 32];

        let iterations = vec_iterations.read_u32::<LittleEndian>()?;
        salt.copy_from_slice(&data[4..36]);
        hash.copy_from_slice(&data[36..]);

        Ok(PasswordHashV1 {
            iterations,
            salt,
            hash,
        })
    }
}

impl PasswordHashV1 {
    pub fn hash_password(pass: &[u8], iterations: u32) -> PasswordHashV1 {
        // Generate salt
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        // Generate hash
        let mut hash = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(pass, &salt, iterations, &mut hash);

        PasswordHashV1 {
            iterations,
            salt,
            hash,
        }
    }

    pub fn verify_password(&self, pass: &[u8]) -> bool {
        let mut res = vec![0u8; 32];
        pbkdf2::<Hmac<Sha256>>(pass, &self.salt, self.iterations, &mut res);

        let is_equal = res.ct_eq(&self.hash).into();

        res.zeroize();
        is_equal
    }
}
