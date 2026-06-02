use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::ciphertext::Ciphertext;
use crate::key_derivation::DerivationParameters;
use crate::{Error, Result};

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct KdfEncryptedDataV1 {
    pub derivation_parameters: DerivationParameters,
    pub ciphertext: Ciphertext,
}

impl From<&KdfEncryptedDataV1> for Vec<u8> {
    fn from(data: &KdfEncryptedDataV1) -> Self {
        let derivation_parameters: Vec<u8> = data.derivation_parameters.clone().into();
        let ciphertext: Vec<u8> = data.ciphertext.clone().into();

        let mut serialized =
            Vec::with_capacity(8 + derivation_parameters.len() + ciphertext.len());

        serialized
            .write_u32::<LittleEndian>(derivation_parameters.len() as u32)
            .unwrap();
        serialized
            .write_u32::<LittleEndian>(ciphertext.len() as u32)
            .unwrap();
        serialized.write_all(&derivation_parameters).unwrap();
        serialized.write_all(&ciphertext).unwrap();

        serialized
    }
}

impl TryFrom<&[u8]> for KdfEncryptedDataV1 {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::InvalidLength);
        }

        let mut cursor = Cursor::new(data);

        let derivation_parameters_length = cursor.read_u32::<LittleEndian>()? as usize;
        let ciphertext_length = cursor.read_u32::<LittleEndian>()? as usize;

        let total_expected = 8usize
            .checked_add(derivation_parameters_length)
            .and_then(|x| x.checked_add(ciphertext_length))
            .ok_or(Error::InvalidLength)?;

        if data.len() != total_expected {
            return Err(Error::InvalidLength);
        }

        let mut derivation_parameters_raw = vec![0u8; derivation_parameters_length];
        cursor.read_exact(&mut derivation_parameters_raw)?;

        let mut ciphertext_raw = vec![0u8; ciphertext_length];
        cursor.read_exact(&mut ciphertext_raw)?;

        Ok(Self {
            derivation_parameters: DerivationParameters::try_from(derivation_parameters_raw.as_slice())?,
            ciphertext: Ciphertext::try_from(ciphertext_raw.as_slice())?,
        })
    }
}
