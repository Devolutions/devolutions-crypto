use std::{
    convert::TryFrom,
    io::{Cursor, Read, Write},
};

use argon2::{Config, Variant, Version};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::TryRngCore;
use typed_builder::TypedBuilder;

#[cfg(feature = "wbindgen")]
use wasm_bindgen::prelude::*;

use super::Error;
use super::Result;

pub mod defaults {
    use super::Error;
    use super::Result;
    use argon2::Variant;
    use argon2::Version;
    use rand::TryRngCore;

    pub const LENGTH: u32 = 32;
    pub const LANES: u32 = 1;
    pub const MEMORY: u32 = 4096;
    pub const ITERATIONS: u32 = 2;
    pub const VARIANT: Variant = Variant::Argon2id;
    pub const VERSION: Version = Version::Version13;
    pub const DC_VERSION: u32 = 1;

    pub fn salt() -> Result<Vec<u8>> {
        let mut salt = vec![0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(salt.as_mut_slice())
            .map_err(|_| Error::RandomError)?;
        Ok(salt)
    }
}

/// Parameters used to derive the password into an Argon2 hash.
///
/// It is used to derive a password into a keypair.
/// You should use the default, although this may be tweakable by the user in some cases.
/// Once serialized, you can save it along the user information as it is not sensitive data.
/// If the hash should never be computed in a non-threaded environment,
///  you can raise the "lanes" value to enable multi-threading.
///
/// Note that calling `default()` will also generate a new random salt,
///  so two calls to `default()` will not generate the same structure.
#[cfg_attr(feature = "wbindgen", wasm_bindgen(inspectable))]
#[derive(Clone, TypedBuilder)]
pub struct Argon2Parameters {
    /// Length of the desired hash. Should be 32 in most case.
    #[builder(default=defaults::LENGTH)]
    pub length: u32,
    /// Number of parallel jobs to run. Only use if always computed in a multithreaded environment.
    #[builder(default=defaults::LANES)]
    pub lanes: u32,
    /// Memory used by the algorithm in KiB. Higher is better.
    #[builder(default=defaults::MEMORY)]
    pub memory: u32,
    /// Number of iterations(time cost). Higher is better.
    #[builder(default=defaults::ITERATIONS)]
    pub iterations: u32,
    /// The variant to use. You should almost always use Argon2Id.
    #[builder(default=defaults::VARIANT)]
    variant: Variant,
    /// The version of Argon2 to use. Use the latest.
    #[builder(default=defaults::VERSION)]
    version: Version,
    /// Version of this structure in DevolutionsCrypto.
    #[builder(default=defaults::DC_VERSION)]
    dc_version: u32,
    /// Authenticated but not secret data.
    #[builder(default)]
    associated_data: Vec<u8>,
    /// Secret key to sign the hash. Note that this is not serialized.
    #[builder(default)]
    secret_key: Vec<u8>,
    /// A 16-bytes salt to use that is generated automatically. Should not be accessed directly.
    #[builder(default = defaults::salt().unwrap())]
    salt: Vec<u8>,
}

impl Argon2Parameters {
    pub fn get_salt_as_slice(&self) -> &[u8] {
        self.salt.as_slice()
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) {
        self.salt = salt;
    }
}

/// Implements the default parameters.
impl Default for Argon2Parameters {
    fn default() -> Self {
        let mut salt = vec![0u8; 16];

        rand::rngs::OsRng
            .try_fill_bytes(salt.as_mut_slice())
            .unwrap();

        Argon2Parameters {
            associated_data: Vec::new(),
            secret_key: Vec::new(),
            length: 32,
            lanes: 1,
            memory: 4096,
            iterations: 2,
            variant: Variant::Argon2id,
            version: Version::Version13,
            dc_version: 1,
            salt,
        }
    }
}

impl From<&Argon2Parameters> for Vec<u8> {
    fn from(params: &Argon2Parameters) -> Self {
        // Data is encoded this way:
        // All the u32 data -> enums(as u8) -> Vectors(length as u32 + vec))
        // Note that the secret key is not serialized.
        // Length is calculated this way:
        // 5 * u32 + 2 * u8(enums) + 3 *u32(lengths) + 2 * vec.len();
        let mut data = Vec::with_capacity(
            5 * 4 + 2 + 2 * 4 + params.associated_data.len() + params.salt.len(),
        );
        data.write_u32::<LittleEndian>(params.dc_version).unwrap();
        data.write_u32::<LittleEndian>(params.length).unwrap();
        data.write_u32::<LittleEndian>(params.lanes).unwrap();
        data.write_u32::<LittleEndian>(params.memory).unwrap();
        data.write_u32::<LittleEndian>(params.iterations).unwrap();
        data.write_u8(params.variant.as_u32() as u8).unwrap();
        data.write_u8(params.version.as_u32() as u8).unwrap();

        data.write_u32::<LittleEndian>(params.associated_data.len() as u32)
            .unwrap();

        data.write_all(&params.associated_data).unwrap();

        data.write_u32::<LittleEndian>(params.salt.len() as u32)
            .unwrap();

        data.write_all(&params.salt).unwrap();

        data
    }
}

impl TryFrom<&[u8]> for Argon2Parameters {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let mut data_cursor = Cursor::new(data);
        let dc_version = data_cursor.read_u32::<LittleEndian>()?;
        let length = data_cursor.read_u32::<LittleEndian>()?;
        let lanes = data_cursor.read_u32::<LittleEndian>()?;
        let memory = data_cursor.read_u32::<LittleEndian>()?;
        let iterations = data_cursor.read_u32::<LittleEndian>()?;

        // Check if the versions works
        let (variant, version) = match (
            Variant::from_u32(data_cursor.read_u8()? as u32),
            Version::from_u32(data_cursor.read_u8()? as u32),
        ) {
            (Ok(variant), Ok(version)) => (variant, version),
            _ => return Err(Error::InvalidData),
        };

        let associated_data_length = data_cursor.read_u32::<LittleEndian>()? as usize;
        let remaining = data.len() - (data_cursor.position() as usize);
        if remaining < associated_data_length {
            return Err(Error::InvalidLength);
        }

        let mut associated_data = vec![0u8; associated_data_length];
        data_cursor.read_exact(&mut associated_data)?;

        let salt_length = data_cursor.read_u32::<LittleEndian>()? as usize;
        let remaining = data.len() - (data_cursor.position() as usize);
        if remaining < salt_length {
            return Err(Error::InvalidLength);
        }

        let mut salt = vec![0u8; salt_length];
        data_cursor.read_exact(&mut salt)?;

        Ok(Argon2Parameters {
            associated_data,
            secret_key: Vec::new(),
            length,
            lanes,
            memory,
            iterations,
            variant,
            version,
            dc_version,
            salt,
        })
    }
}

impl Argon2Parameters {
    /// Compute the Argon2 hash using the password and the parameters.
    pub fn compute(&self, password: &[u8]) -> Result<Vec<u8>> {
        let config = Config {
            ad: &self.associated_data,
            secret: &self.secret_key,
            hash_length: self.length,
            lanes: self.lanes,
            mem_cost: self.memory,
            time_cost: self.iterations,
            variant: self.variant,
            version: self.version,
        };

        Ok(argon2::hash_raw(password, &self.salt, &config)?)
    }
}

#[test]
fn test_argon2() {
    use std::convert::TryInto;

    let mut config = Argon2Parameters::default();
    config.iterations = 2;
    config.memory = 32;

    // Computes the first hash
    let hash1 = config.compute(b"Password1").unwrap();
    let config_vec: Vec<u8> = (&config).into();

    assert_ne!(config_vec.len(), 0);

    let config: Argon2Parameters = config_vec.as_slice().try_into().unwrap();

    // Compute a 2nd hash with the same params
    let hash2 = config.compute(b"Password1").unwrap();

    // Same params, different password.
    let hash3 = config.compute(b"Password2").unwrap();

    // Same Params, Same password, different salt
    let mut config = Argon2Parameters::default();
    config.iterations = 2;
    config.memory = 32;
    let hash4 = config.compute(b"Password1").unwrap();

    // Test length params.
    let mut config5 = Argon2Parameters::default();
    config5.iterations = 2;
    config5.memory = 32;
    config5.length = 41;
    let hash5 = config5.compute(b"Password1").unwrap();

    assert_eq!(hash1.len(), config.length as usize);
    assert_eq!(hash1, hash2);
    assert_ne!(hash1, hash3);
    assert_ne!(hash1, hash4);
    assert_eq!(hash5.len(), config5.length as usize);
}
