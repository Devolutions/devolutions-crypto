use super::DevoCryptoError;
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

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DcPasswordHashV1 {
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

impl From<DcPasswordHashV1> for Vec<u8> {
    fn from(mut hash: DcPasswordHashV1) -> Vec<u8> {
        let iterations = hash.iterations;
        let mut data = Vec::with_capacity(4);
        data.write_u32::<LittleEndian>(iterations).unwrap();

        data.append(&mut hash.salt);
        data.append(&mut hash.hash);

        data
    }
}

impl TryFrom<&[u8]> for DcPasswordHashV1 {
    type Error = DevoCryptoError;

    fn try_from(data: &[u8]) -> Result<DcPasswordHashV1> {
        if data.len() != 68 {
            return Err(DevoCryptoError::InvalidLength);
        };

        let mut vec_iterations = Cursor::new(&data[0..4]);
        let mut salt = vec![0u8; 32];
        let mut hash = vec![0u8; 32];

        let iterations = vec_iterations.read_u32::<LittleEndian>()?;
        salt.copy_from_slice(&data[4..36]);
        hash.copy_from_slice(&data[36..]);

        Ok(DcPasswordHashV1 {
            iterations,
            salt,
            hash,
        })
    }
}

impl DcPasswordHashV1 {
    pub fn hash_password(pass: &[u8], iterations: u32) -> Result<DcPasswordHashV1> {
        // Generate salt
        let mut salt = vec![0u8; 32];
        OsRng.fill_bytes(&mut salt);

        // Generate password_hash
        let mut hash = vec![0u8; 32];
        pbkdf2::<Hmac<Sha256>>(pass, &salt, iterations as usize, &mut hash);

        Ok(DcPasswordHashV1 {
            iterations,
            salt,
            hash,
        })
    }

    pub fn verify_password(&self, pass: &[u8]) -> Result<bool> {
        let mut res = vec![0u8; 32];
        pbkdf2::<Hmac<Sha256>>(pass, &self.salt, self.iterations as usize, &mut res);

        let is_equal = res.ct_eq(&self.hash).into();

        res.zeroize();
        Ok(is_equal)
    }
}