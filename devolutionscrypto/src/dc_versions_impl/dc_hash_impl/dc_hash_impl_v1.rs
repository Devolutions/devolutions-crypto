use super::DcHeader;
use super::DcSerialize;
use super::DevoCryptoError;
use super::HashImpl;
use super::Result;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::{rngs::OsRng, RngCore};
use std::io::Cursor;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

pub struct DcHashImplV1 {
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

impl HashImpl for DcHashImplV1 {
    fn hash(data: &[u8], iterations: u32) -> Result<Self> {
        // Generate salt
        let mut rng = OsRng::new()?;
        let mut salt = vec![0u8; 32];
        rng.fill_bytes(&mut salt);

        // Generate hash
        let mut hash = vec![0u8; 32];
        pbkdf2::<Hmac<Sha256>>(data, &salt, iterations as usize, &mut hash);

        Ok(DcHashImplV1 {
            iterations,
            salt,
            hash,
        })
    }

    fn verify(data: &[u8], hash: &[u8]) -> Result<bool> {
        // Verify signature
        let signature = &hash[0..4];

        if signature != [0x0D, 0x0D, 0x01, 0x00] {
            return Err(DevoCryptoError::InvalidSignature);
        }

        // Get metadata
        let mut vec_iterations = Cursor::new(&hash[4..8]);
        let niterations = vec_iterations.read_u32::<LittleEndian>()?;
        let salt = &hash[8..40];

        let mut res = vec![0u8; 32];

        pbkdf2::<Hmac<Sha256>>(data, salt, niterations as usize, &mut res);

        Ok(res == &hash[40..])
    }
}

impl DcSerialize for DcHashImplV1 {
    fn try_from_header(data: &[u8], _header: &DcHeader) -> Result<Self> {
        let mut vec_iterations = Cursor::new(&data[0..4]);
        let mut salt = Vec::with_capacity(32);
        let mut hash = Vec::with_capacity(32);

        let iterations = vec_iterations.read_u32::<LittleEndian>()?;
        salt.copy_from_slice(&data[4..36]);
        hash.copy_from_slice(&data[36..]);

        Ok(DcHashImplV1 {
            iterations,
            salt,
            hash,
        })
    }

    fn into_vec(&mut self) -> Vec<u8> {
        let iterations = self.iterations;
        let mut data = Vec::with_capacity(4);
        data.write_u32::<LittleEndian>(iterations).unwrap();

        data.append(&mut self.salt);
        data.append(&mut self.hash);

        data
    }
}
