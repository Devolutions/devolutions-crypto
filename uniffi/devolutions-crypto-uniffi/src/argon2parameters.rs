use crate::Result;

use devolutions_crypto::{Argon2Variant, Argon2Version};

use uniffi_builder_macro::UniffiBuilder;

#[UniffiBuilder(Argon2Parameters, devolutions_crypto::argon2parameters_defaults)]
pub struct Argon2ParametersBuilder {
    length: u32,
    lanes: u32,
    memory: u32,
    iterations: u32,
    variant: Argon2Variant,
    version: Argon2Version,
    dc_version: u32,

    #[builder_default = Default::default()]
    associated_data: Vec<u8>,

    #[builder_default = Default::default()]
    secret_key: Vec<u8>,

    #[builder_default = devolutions_crypto::argon2parameters_defaults::salt()]
    salt: Vec<u8>,
}

pub struct Argon2Parameters(pub devolutions_crypto::Argon2Parameters);

impl Argon2Parameters {
    pub fn new_from_bytes(data: &[u8]) -> Result<Self> {
        let data = data.try_into()?;
        Ok(Self(data))
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        (&self.0).into()
    }

    fn get_inner_builder() -> devolutions_crypto::Argon2ParametersBuilder {
        devolutions_crypto::Argon2Parameters::builder()
    }
}
