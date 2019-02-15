use super::DcHeader;
use super::Result;

pub struct DcCiphertext {
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    hmac: Vec<u8>,
}

impl Drop for DcCiphertext {
    fn drop(&mut self) {
        for b in &mut self.iv {
            *b = 0;
        }
        for b in &mut self.ciphertext {
            *b = 0;
        }
        for b in &mut self.hmac {
            *b = 0;
        }
    }
}

impl Into<Vec<u8>> for DcCiphertext {
    fn into(mut self) -> Vec<u8> {
        let mut data = Vec::new();
        data.append(&mut self.iv);
        data.append(&mut self.ciphertext);
        data.append(&mut self.hmac);
        data
    }
}

impl DcCiphertext {
    pub fn try_from_header(data: &[u8], _header: &DcHeader) -> Result<DcCiphertext> {
        let mut iv = Vec::with_capacity(16);
        let mut ciphertext = Vec::new();
        let mut hmac = Vec::with_capacity(32);

        iv.copy_from_slice(&data[0..16]);
        ciphertext.copy_from_slice(&data[0..data.len() - 32]);
        hmac.copy_from_slice(&data[data.len() - 32..]);

        Ok(DcCiphertext {
            iv,
            ciphertext,
            hmac,
        })
    }
}
