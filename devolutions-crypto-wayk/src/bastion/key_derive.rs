use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;

/// Derives tenant key from subscription master key and tenant UUID
pub fn derive_tenant_key(
    subscription_id: Uuid,
    tenant_id: Uuid,
    subscription_master_key: &[u8],
) -> Vec<u8> {
    derive_key_impl(subscription_id, tenant_id, subscription_master_key, 64)
        .expect("64 is a valid length for Sha256 to output")
}

/// Derives resource key from tenant key and resource UUID
pub fn derive_resource_key(tenant_id: Uuid, resource_id: Uuid, tenant_key: &[u8]) -> Vec<u8> {
    derive_key_impl(tenant_id, resource_id, tenant_key, 32)
        .expect("32 is a valid length for Sha256 to output")
}

/// Internal helper for sub key derivation
///
/// # Internals
///
/// HKDF procedure for derivating a sub key from a UUID used as salt
/// another UUID used as info string, and some input key (IKM, Input Keying Material).
/// `output_len` is our L argument, length of output keying material
/// in octets (must be <= 255 * Sha256 hash len)
fn derive_key_impl(
    salt_id: Uuid,
    info_id: Uuid,
    ikm: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, hkdf::InvalidLength> {
    let salt = salt_id.as_bytes(); // `as_bytes` gives us UUID big-endian representation
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);

    let info = info_id.as_bytes(); // `as_bytes` gives us UUID big-endian representation
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)?;

    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER_KEY: &[u8] = &[
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    ];
    const TENANT_KEY: &[u8] = &[
        96, 43, 179, 189, 52, 54, 16, 112, 73, 201, 96, 83, 242, 86, 0, 244, 216, 59, 85, 249, 17,
        165, 51, 172, 183, 195, 247, 209, 65, 52, 234, 91, 7, 25, 127, 192, 28, 195, 248, 231, 240,
        32, 180, 113, 213, 238, 234, 48, 239, 8, 146, 132, 21, 166, 199, 250, 57, 96, 184, 71, 90,
        118, 216, 109,
    ];
    const RESOURCE_KEY: &[u8] = &[
        189, 72, 50, 73, 241, 119, 140, 134, 238, 246, 196, 220, 22, 110, 240, 26, 66, 132, 74, 67,
        250, 203, 21, 31, 138, 56, 229, 130, 252, 157, 13, 32,
    ];

    const SUBSCRIPTION_ID: Uuid = Uuid::from_u128(32);
    const TENANT_ID: Uuid = Uuid::from_u128(64);
    const RESOURCE_ID: Uuid = Uuid::from_u128(128);

    /// Sanity check, just in case `Uuid::as_bytes` stops giving us big-endian binary
    /// representation.
    #[test]
    fn uuid_as_bytes_is_big_endian() {
        assert_eq!(
            SUBSCRIPTION_ID.as_bytes(),
            &SUBSCRIPTION_ID.as_u128().to_be_bytes()
        );
        assert_eq!(TENANT_ID.as_bytes(), &TENANT_ID.as_u128().to_be_bytes());
        assert_eq!(RESOURCE_ID.as_bytes(), &RESOURCE_ID.as_u128().to_be_bytes());
    }

    /// Sanity check, given the same input derivated key should never change
    #[test]
    fn tenant_key() {
        let derived_tenant_key = derive_tenant_key(SUBSCRIPTION_ID, TENANT_ID, MASTER_KEY);
        assert_eq!(derived_tenant_key.len(), 64);
        assert_eq!(derived_tenant_key, TENANT_KEY);
    }

    /// Sanity check, given the same input derivated key should never change
    #[test]
    fn resource_key() {
        let derived_resource_key = derive_resource_key(TENANT_ID, RESOURCE_ID, TENANT_KEY);
        assert_eq!(derived_resource_key.len(), 32);
        assert_eq!(derived_resource_key, RESOURCE_KEY);
    }
}
