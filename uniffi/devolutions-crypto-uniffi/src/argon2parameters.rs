use std::sync::{Arc, Mutex};

use crate::Result;
use devolutions_crypto::argon2parameters_defaults;
use devolutions_crypto::{Argon2Variant, Argon2Version};

pub struct Argon2ParametersBuilder {
    length: Mutex<u32>,
    lanes: Mutex<u32>,
    memory: Mutex<u32>,
    iterations: Mutex<u32>,
    variant: Mutex<Argon2Variant>,
    version: Mutex<Argon2Version>,
    dc_version: Mutex<u32>,
    associated_data: Mutex<Vec<u8>>,
    secret_key: Mutex<Vec<u8>>,
    salt: Mutex<Vec<u8>>,
}

impl Clone for Argon2ParametersBuilder {
    fn clone(&self) -> Self {
        Self {
            length: Mutex::new(self.length.lock().unwrap().clone()),
            lanes: Mutex::new(self.lanes.lock().unwrap().clone()),
            memory: Mutex::new(self.memory.lock().unwrap().clone()),
            iterations: Mutex::new(self.iterations.lock().unwrap().clone()),
            variant: Mutex::new(self.variant.lock().unwrap().clone()),
            version: Mutex::new(self.version.lock().unwrap().clone()),
            dc_version: Mutex::new(self.dc_version.lock().unwrap().clone()),
            associated_data: Mutex::new(self.associated_data.lock().unwrap().clone()),
            secret_key: Mutex::new(self.secret_key.lock().unwrap().clone()),
            salt: Mutex::new(self.salt.lock().unwrap().clone()),
        }
    }
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
}

impl Argon2ParametersBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn length(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.length.lock().unwrap() = value;
        self
    }

    pub fn lanes(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.lanes.lock().unwrap() = value;
        self
    }

    pub fn memory(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.memory.lock().unwrap() = value;
        self
    }

    pub fn iterations(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.iterations.lock().unwrap() = value;
        self
    }

    pub fn variant(self: Arc<Self>, value: Argon2Variant) -> Arc<Self> {
        *self.variant.lock().unwrap() = value;
        self
    }

    pub fn version(self: Arc<Self>, value: Argon2Version) -> Arc<Self> {
        *self.version.lock().unwrap() = value;
        self
    }

    pub fn dc_version(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.dc_version.lock().unwrap() = value;
        self
    }

    pub fn associated_data(self: Arc<Self>, value: Vec<u8>) -> Arc<Self> {
        *self.associated_data.lock().unwrap() = value;
        self
    }

    pub fn secret_key(self: Arc<Self>, value: Vec<u8>) -> Arc<Self> {
        *self.secret_key.lock().unwrap() = value;
        self
    }

    pub fn salt(self: Arc<Self>, value: Vec<u8>) -> Arc<Self> {
        *self.salt.lock().unwrap() = value;
        self
    }

    pub fn build(self: Arc<Self>) -> Arc<Argon2Parameters> {
        let builder = Arc::<Argon2ParametersBuilder>::unwrap_or_clone(self);

        Argon2Parameters(
            devolutions_crypto::Argon2Parameters::builder()
                .length(builder.length.into_inner().unwrap())
                .lanes(builder.lanes.into_inner().unwrap())
                .memory(builder.memory.into_inner().unwrap())
                .iterations(builder.iterations.into_inner().unwrap())
                .variant(builder.variant.into_inner().unwrap())
                .version(builder.version.into_inner().unwrap())
                .dc_version(builder.dc_version.into_inner().unwrap())
                .associated_data(builder.associated_data.into_inner().unwrap())
                .secret_key(builder.secret_key.into_inner().unwrap())
                .salt(builder.salt.into_inner().unwrap())
                .build(),
        )
        .into()
    }
}

impl Default for Argon2ParametersBuilder {
    fn default() -> Self {
        Self {
            length: Mutex::new(argon2parameters_defaults::LENGTH),
            lanes: Mutex::new(argon2parameters_defaults::LANES),
            memory: Mutex::new(argon2parameters_defaults::MEMORY),
            iterations: Mutex::new(argon2parameters_defaults::ITERATIONS),
            variant: Mutex::new(argon2parameters_defaults::VARIANT),
            version: Mutex::new(argon2parameters_defaults::VERSION),
            dc_version: Mutex::new(argon2parameters_defaults::DC_VERSION),
            associated_data: Mutex::new(Default::default()),
            secret_key: Mutex::new(Default::default()),
            salt: Mutex::new(argon2parameters_defaults::salt()),
        }
    }
}
