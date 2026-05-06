# Plan: Add SecretKey type for symmetric encryption

## TL;DR
Add a wrapped `SecretKey` type (DataType::Key + KeySubtype::Secret) analogous to `PrivateKey`/`PublicKey`, backed by 32 raw random bytes. Provide typed encrypt/decrypt methods on the ciphertext module so callers pass `&SecretKey` instead of `&[u8]`. Include unit tests and a conformity test.

## Phase 1 — Enum & Core Type

1. **Add `Secret = 4` to `KeySubtype`** in `src/enums.rs`.

2. **Create `src/key/secret_key_v1.rs`** with:
   - `pub struct SecretKeyV1 { key: Zeroizing<[u8; 32]> }`
   - `generate() -> SecretKeyV1` using `rand::rngs::OsRng`
   - `as_bytes(&self) -> &[u8]`
   - `impl TryFrom<&[u8]> for SecretKeyV1` — validate len == 32
   - `impl From<SecretKeyV1> for Vec<u8>`

3. **Add `SecretKey` to `src/key/mod.rs`** (parallel to `PrivateKey`):
   - `pub struct SecretKey { pub(crate) header: Header<SecretKey>, payload: SecretKeyPayload }`
   - `enum SecretKeyPayload { V1(SecretKeyV1) }`
   - `impl HeaderType for SecretKey` → `data_type() = DataType::Key`, `subtype() = KeySubtype::Secret`, `Version = KeyVersion`
   - `impl From<SecretKey> for Vec<u8>` — header + payload (follows exact PrivateKey pattern)
   - `impl TryFrom<&[u8]> for SecretKey` — validates `header.data_subtype == KeySubtype::Secret`, then dispatches on version
   - `pub fn generate_secret_key(version: KeyVersion) -> SecretKey`
   - `impl SecretKey { pub fn as_bytes(&self) -> &[u8] }` — exposes key material for internal use by ciphertext module
   - Add `mod secret_key_v1;` declaration

## Phase 2 — Ciphertext Module Overloads

4. **Add typed encrypt/decrypt to `src/ciphertext/mod.rs`**:
   - Free function: `pub fn encrypt_with_secret_key(data: &[u8], key: &SecretKey, version: CiphertextVersion) -> Result<Ciphertext>` — delegates to `encrypt(data, key.as_bytes(), version)`
   - Free function: `pub fn encrypt_with_secret_key_and_aad(data: &[u8], key: &SecretKey, aad: &[u8], version: CiphertextVersion) -> Result<Ciphertext>` — delegates to `encrypt_with_aad`
   - Method: `impl Ciphertext { pub fn decrypt_with_secret_key(&self, key: &SecretKey) -> Result<Vec<u8>> }` — delegates to `self.decrypt(key.as_bytes())`
   - Method: `impl Ciphertext { pub fn decrypt_with_secret_key_and_aad(&self, key: &SecretKey, aad: &[u8]) -> Result<Vec<u8>> }` — delegates to `self.decrypt_with_aad`
   - Add `use super::key::SecretKey;` import

## Phase 3 — Exports

5. **Update `src/lib.rs`**:
   - Add `KeySubtype` to the `pub use enums::{ ... }` re-export list
   - Add `SecretKey` and `generate_secret_key` to `pub use key::{ ... }` or ensure they're accessible via `pub mod key`

## Phase 4 — Tests

6. **Unit tests in `src/key/mod.rs`** (inside `#[cfg(test)]` block):
   - `secret_key_generate_roundtrip` — generate → serialize to bytes → deserialize → verify as_bytes round-trips
   - `secret_key_wrong_subtype_rejected` — try_from a PrivateKey bytes slice as SecretKey should return `Err(InvalidDataType)`
   - `secret_key_wrong_length_rejected` — too-short byte slice returns `Err(InvalidLength)`

7. **Unit tests in `src/ciphertext/mod.rs`**:
   - `encrypt_decrypt_with_secret_key` — generate key, encrypt, decrypt, assert plaintext equality
   - `encrypt_decrypt_with_secret_key_aad` — same with AAD; also verify wrong AAD returns error
   - `encrypt_decrypt_with_secret_key_v1` and `_v2` — explicit version coverage

8. **Conformity test in `tests/conformity.rs`**:
   - `test_symmetric_decrypt_with_secret_key_v2` — parse a known-good SecretKey from base64, decrypt a known ciphertext, assert result == expected plaintext. (Test vector generated during implementation from the existing known symmetric key `ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=` wrapped in a SecretKey header.)

## Relevant files
- `src/enums.rs` — add `Secret = 4` to `KeySubtype`
- `src/key/mod.rs` — add `SecretKey`, `SecretKeyPayload`, `generate_secret_key`, conversions; reference the `PrivateKey` impl at lines 82–241 as the template
- `src/key/secret_key_v1.rs` — new file; use `key_v1.rs` TryFrom/From pattern as reference
- `src/ciphertext/mod.rs` — add 4 typed encrypt/decrypt wrappers; reference `decrypt_asymmetric` (lines ~230) for method placement
- `src/lib.rs` — update re-exports
- `tests/conformity.rs` — add conformity test

## Verification
1. `cargo test` — all tests pass
2. `cargo check` — no type errors
3. Confirm `SecretKey::try_from(private_key_bytes)` returns `Err(InvalidDataType)`
4. Confirm `PrivateKey::try_from(secret_key_bytes)` returns `Err(InvalidDataType)`
5. Conformity test decrypts known test vector correctly

## Decisions
- **Reuse `KeyVersion`** for SecretKey (same as PrivateKey/PublicKey) — since the version here is about the raw format (32-byte block), not the cryptographic algorithm. `V1 = 32 random bytes`.
- **`as_bytes()` method** on SecretKey exposes raw bytes for delegation to existing encrypt/decrypt internals — avoids duplicating encryption logic.
- **Scope: Rust core library only.** FFI (`ffi/src/lib.rs`), WASM (`src/wasm.rs`), UniFFI (`uniffi/`), C# wrapper, Kotlin/Swift/Python wrappers are out of scope for this plan. They follow the same patterns and can be addressed in a follow-up.
- `SecretKeyV1` uses `Zeroizing<[u8; 32]>` to ensure key material is cleared from memory on drop.
