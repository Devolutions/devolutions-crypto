use crate::{Argon2Variant, Argon2Version, Result};
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object)]
pub struct Argon2ParametersBuilder {
    length: Mutex<Option<u32>>,
    lanes: Mutex<Option<u32>>,
    memory: Mutex<Option<u32>>,
    iterations: Mutex<Option<u32>>,
    variant: Mutex<Option<Argon2Variant>>,
    version: Mutex<Option<Argon2Version>>,
    dc_version: Mutex<Option<u32>>,
    associated_data: Mutex<Option<Vec<u8>>>,
    secret_key: Mutex<Option<Vec<u8>>>,
    salt: Mutex<Option<Vec<u8>>>,
}

#[uniffi::export]
impl Argon2ParametersBuilder {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            length: Mutex::new(None),
            lanes: Mutex::new(None),
            memory: Mutex::new(None),
            iterations: Mutex::new(None),
            variant: Mutex::new(None),
            version: Mutex::new(None),
            dc_version: Mutex::new(None),
            associated_data: Mutex::new(None),
            secret_key: Mutex::new(None),
            salt: Mutex::new(None),
        })
    }

    pub fn length(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.length.lock().unwrap() = Some(value);
        self
    }

    pub fn lanes(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.lanes.lock().unwrap() = Some(value);
        self
    }

    pub fn memory(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.memory.lock().unwrap() = Some(value);
        self
    }

    pub fn iterations(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.iterations.lock().unwrap() = Some(value);
        self
    }

    pub fn variant(self: Arc<Self>, value: Argon2Variant) -> Arc<Self> {
        *self.variant.lock().unwrap() = Some(value);
        self
    }

    pub fn version(self: Arc<Self>, value: Argon2Version) -> Arc<Self> {
        *self.version.lock().unwrap() = Some(value);
        self
    }

    pub fn dc_version(self: Arc<Self>, value: u32) -> Arc<Self> {
        *self.dc_version.lock().unwrap() = Some(value);
        self
    }

    pub fn associated_data(self: Arc<Self>, value: Vec<u8>) -> Arc<Self> {
        *self.associated_data.lock().unwrap() = Some(value);
        self
    }

    pub fn secret_key(self: Arc<Self>, value: Vec<u8>) -> Arc<Self> {
        *self.secret_key.lock().unwrap() = Some(value);
        self
    }

    pub fn salt(self: Arc<Self>, value: Vec<u8>) -> Arc<Self> {
        *self.salt.lock().unwrap() = Some(value);
        self
    }

    pub fn build(self: Arc<Self>) -> Arc<Argon2Parameters> {
        // Get all the values
        let length = *self.length.lock().unwrap();
        let lanes = *self.lanes.lock().unwrap();
        let memory = *self.memory.lock().unwrap();
        let iterations = *self.iterations.lock().unwrap();
        let variant = *self.variant.lock().unwrap();
        let version = *self.version.lock().unwrap();
        let dc_version = *self.dc_version.lock().unwrap();
        let associated_data = self.associated_data.lock().unwrap().clone();
        let secret_key = self.secret_key.lock().unwrap().clone();
        let salt = self.salt.lock().unwrap().clone();

        // Build by chaining all fields together (typed-builder requires all fields to be set)
        let inner =
            devolutions_crypto::Argon2Parameters::builder()
                .length(length.unwrap_or(32))
                .lanes(lanes.unwrap_or(1))
                .memory(memory.unwrap_or(4096))
                .iterations(iterations.unwrap_or(3))
                .variant(
                    variant
                        .map(|v| v.into())
                        .unwrap_or(argon2::Variant::Argon2id),
                )
                .version(
                    version
                        .map(|v| v.into())
                        .unwrap_or(argon2::Version::Version13),
                )
                .dc_version(dc_version.unwrap_or(1))
                .associated_data(associated_data.unwrap_or_default())
                .secret_key(secret_key.unwrap_or_default())
                .salt(salt.unwrap_or_else(|| {
                    devolutions_crypto::argon2parameters_defaults::salt().unwrap()
                }))
                .build();

        Arc::new(Argon2Parameters { inner })
    }
}

#[derive(uniffi::Object)]
pub struct Argon2Parameters {
    pub(crate) inner: devolutions_crypto::Argon2Parameters,
}

#[uniffi::export]
impl Argon2Parameters {
    #[uniffi::constructor]
    pub fn new_from_bytes(data: &[u8]) -> Result<Arc<Self>> {
        let inner = data.try_into()?;
        Ok(Arc::new(Self { inner }))
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        (&self.inner).into()
    }
}
