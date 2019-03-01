use std::convert::TryFrom;

use rand::{rngs::OsRng, RngCore};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;


use super::Result;
use super::DevoCryptoError;

pub struct DcHashV1 {
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

impl Into<Vec<u8>> for DcHashV1 {
    fn into(mut self) -> Vec<u8> {
        let iterations = self.iterations;
        let mut data = Vec::with_capacity(4);
        data.write_u32::<LittleEndian>(iterations).unwrap();

        data.append(&mut self.salt);
        data.append(&mut self.hash);

        data
    }
}

impl TryFrom<&[u8]> for DcHashV1 {
    type Error = DevoCryptoError;

    fn try_from(data: &[u8]) -> Result<DcHashV1> {
        let mut vec_iterations = Cursor::new(&data[0..4]);
        let mut salt = Vec::with_capacity(32);
        let mut hash = Vec::with_capacity(32);

        let iterations = vec_iterations.read_u32::<LittleEndian>()?;
        salt.copy_from_slice(&data[4..36]);
        hash.copy_from_slice(&data[36..]);

        Ok(DcHashV1 {
            iterations,
            salt,
            hash,
        })
    }
}

impl DcHashV1 {
    pub fn hash_password(pass: &[u8], iterations: u32) -> Result<DcHashV1> {
        // Generate salt
        let mut rng = OsRng::new()?;
        let mut salt = vec![0u8; 32];
        rng.fill_bytes(&mut salt);

        // Generate hash
        let mut hash = vec![0u8; 32];
        pbkdf2::<Hmac<Sha256>>(pass, &salt, iterations as usize, &mut hash);

        Ok(DcHashV1 {
            iterations,
            salt,
            hash,
        })
    }

    pub fn verify_password(&self, pass: &[u8]) -> Result<bool> {
        let mut res = vec![0u8; 32];
        pbkdf2::<Hmac<Sha256>>(pass, &self.salt, self.iterations as usize, &mut res);
        Ok(self.hash == res)
    }
}