//! Helpers for the `fips` feature.
//!
//! All the version 3 primitives are backed by the AWS-LC FIPS 140-3 validated module.

use super::Error;
use super::Result;

/// Checks that the cryptographic module backing the version 3 primitives runs in FIPS mode.
///
/// The module runs its power-on self-tests the first time it is used. Call this at
/// startup to fail early if the module is not operating in FIPS mode.
/// # Example
/// ```rust
/// devolutions_crypto::fips::ensure_fips_mode().expect("the module should run in FIPS mode");
/// ```
pub fn ensure_fips_mode() -> Result<()> {
    aws_lc_rs::try_fips_mode().map_err(|_| Error::NotFipsApproved)
}
