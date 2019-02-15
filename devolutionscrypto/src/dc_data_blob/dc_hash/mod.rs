use super::DcHeader;

use super::Result;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

pub struct DcHash {
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

impl Drop for DcHash {
    fn drop(&mut self) {
        for b in &mut self.salt {
            *b = 0;
        }
        for b in &mut self.hash {
            *b = 0;
        }
    }
}

impl Into<Vec<u8>> for DcHash {
    fn into(mut self) -> Vec<u8> {
        let iterations = self.iterations;
        let mut data = Vec::with_capacity(4);
        data.write_u32::<LittleEndian>(iterations).unwrap();

        data.append(&mut self.salt);
        data.append(&mut self.hash);

        data
    }
}

impl DcHash {
    pub fn try_from_header(data: &[u8], _header: &DcHeader) -> Result<DcHash> {
        let mut vec_iterations = Cursor::new(&data[0..4]);
        let mut salt = Vec::with_capacity(32);
        let mut hash = Vec::with_capacity(32);

        let iterations = vec_iterations.read_u32::<LittleEndian>()?;
        salt.copy_from_slice(&data[4..36]);
        hash.copy_from_slice(&data[36..]);

        Ok(DcHash {
            iterations,
            salt,
            hash,
        })
    }
}
