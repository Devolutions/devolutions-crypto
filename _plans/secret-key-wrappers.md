# Plan: Expose SecretKey in all language wrappers

## TL;DR
Follow-up to `secret-key.md`. The Rust core now has `SecretKey`, `generate_secret_key`, `encrypt_with_secret_key`, and `decrypt_with_secret_key`. This plan wires them into every language wrapper: FFI/C, C#, WASM/JS, UniFFI (Kotlin + Swift), and Python.

Each wrapper follows its own established pattern for how keys are represented (see per-wrapper sections below).

---

## Phase 1 — FFI / C

### Files
- `ffi/src/lib.rs`
- `ffi/devolutions-crypto.h`

### Changes

The existing `Encrypt`/`Decrypt` FFI functions already accept a raw key buffer, so they already work with the payload bytes of a `SecretKey`. What is missing is a way to generate and serialize a `SecretKey` from C.

1. **Add `GenerateSecretKey`** (writes serialized `SecretKey` bytes into a caller-supplied output buffer):
   ```rust
   #[no_mangle]
   pub unsafe extern "C" fn GenerateSecretKey(
       result: *mut u8,
       result_length: usize,
   ) -> i64
   ```
   Implementation: call `generate_secret_key(KeyVersion::Latest)`, serialize via `Into::<Vec<u8>>::into()`, copy into `result`.

2. **Add `GenerateSecretKeySize`** (returns the byte length of a serialized `SecretKey`):
   ```rust
   #[no_mangle]
   pub extern "C" fn GenerateSecretKeySize() -> i64
   ```
   Implementation: `Header::<SecretKey>::len() + 32` (header size + 32 raw key bytes).  
   Alternatively: generate one and measure — but a constant is cleaner.

3. **Update `ffi/devolutions-crypto.h`** — add the two C declarations:
   ```c
   int64_t GenerateSecretKey(uint8_t *result, size_t result_length);
   int64_t GenerateSecretKeySize(void);
   ```

4. **Add import** `use devolutions_crypto::key::{generate_secret_key, SecretKey, KeyVersion};` to the top of `ffi/src/lib.rs` (alongside existing key imports).

### Tests (in `ffi/src/lib.rs`)
- `generate_secret_key_ffi` — call `GenerateSecretKeySize`, allocate, call `GenerateSecretKey`, parse result with `SecretKey::try_from`, assert 32 bytes.

---

## Phase 2 — C#

### Files
- `wrappers/csharp/src/Native.Core.cs`
- `wrappers/csharp/src/Managed.cs`

### Changes

C# is a thin managed wrapper over the FFI layer. Follow the exact `GenerateKeyPair` pattern.

1. **`Native.Core.cs`** — add two P/Invoke declarations:
   ```csharp
   [DllImport(LibName, EntryPoint = "GenerateSecretKey", CallingConvention = CallingConvention.Cdecl)]
   internal static extern long GenerateSecretKeyNative(byte[] result, UIntPtr resultLength);

   [DllImport(LibName, EntryPoint = "GenerateSecretKeySize", CallingConvention = CallingConvention.Cdecl)]
   internal static extern long GenerateSecretKeySizeNative();
   ```

2. **`Managed.cs`** — add `GenerateSecretKey()` returning a `byte[]`:
   ```csharp
   public static byte[] GenerateSecretKey()
   {
       long size = Native.GenerateSecretKeySizeNative();
       byte[] result = new byte[size];
       long res = Native.GenerateSecretKeyNative(result, (UIntPtr)result.Length);
       if (res < 0) throw DevolutionsCryptoException.FromErrorCode(res);
       return result;
   }
   ```
   Callers then pass the returned `byte[]` to the existing `Encrypt`/`Decrypt` methods directly (no new encrypt/decrypt wrappers needed — `Encrypt(data, secretKeyBytes)` already works).

### Tests (`wrappers/csharp/tests/unit-tests/TestManaged.cs`)
- `GenerateSecretKey` — generate, assert non-null and non-empty, round-trip through `Encrypt`/`Decrypt`, assert equality.

---

## Phase 3 — WASM / JavaScript

### Files
- `src/wasm.rs`

The TypeScript `.d.ts` and the JS glue in `wrappers/wasm/dist/` are generated artifacts — they do not need manual edits.

### Changes

WASM exposes key objects as first-class JS classes (see `PrivateKey`, `PublicKey` pattern). `SecretKey` should follow the same shape.

1. **Import `SecretKey` and `generate_secret_key`** at the top of `src/wasm.rs`:
   ```rust
   use super::{
       key,
       key::{KeyVersion, PrivateKey, PublicKey, SecretKey},
   };
   ```

2. **Implement wasm-bindgen methods on `SecretKey`** (in an `impl` block gated with `#[wasm_bindgen]`):
   ```rust
   #[wasm_bindgen]
   impl SecretKey {
       #[wasm_bindgen(getter)]
       pub fn bytes(&self) -> Vec<u8> {
           self.clone().into()
       }

       #[wasm_bindgen(js_name = "fromBytes")]
       pub fn from_bytes(buffer: &[u8]) -> Result<SecretKey, JsValue> {
           Ok(SecretKey::try_from(buffer)?)
       }
   }
   ```

3. **Add `generateSecretKey` free function**:
   ```rust
   #[wasm_bindgen(js_name = "generateSecretKey")]
   pub fn generate_secret_key(version: Option<KeyVersion>) -> SecretKey {
       key::generate_secret_key(version.unwrap_or(KeyVersion::Latest))
   }
   ```

4. **Add `encryptWithSecretKey` free function** (typed, takes a `SecretKey` object):
   ```rust
   #[wasm_bindgen(js_name = "encryptWithSecretKey")]
   pub fn encrypt_with_secret_key(
       data: &[u8],
       key: &SecretKey,
       aad: Option<Vec<u8>>,
       version: Option<CiphertextVersion>,
   ) -> Result<Vec<u8>, JsValue> {
       Ok(ciphertext::encrypt_with_aad(
           data,
           key.as_bytes(),
           &aad.unwrap_or_default(),
           version.unwrap_or(CiphertextVersion::Latest),
       )?
       .into())
   }
   ```

5. **Add `decryptWithSecretKey` free function**:
   ```rust
   #[wasm_bindgen(js_name = "decryptWithSecretKey")]
   pub fn decrypt_with_secret_key(
       data: &[u8],
       key: &SecretKey,
       aad: Option<Vec<u8>>,
   ) -> Result<Vec<u8>, JsValue> {
       let data_blob = Ciphertext::try_from(data)?;
       Ok(data_blob.decrypt_with_aad(key.as_bytes(), &aad.unwrap_or_default())?)
   }
   ```

### Resulting TypeScript surface (generated)
```ts
export class SecretKey {
  readonly bytes: Uint8Array;
  static fromBytes(buffer: Uint8Array): SecretKey;
}
export function generateSecretKey(version?: KeyVersion | null): SecretKey;
export function encryptWithSecretKey(
  data: Uint8Array,
  key: SecretKey,
  aad?: Uint8Array | null,
  version?: CiphertextVersion | null
): Uint8Array;
export function decryptWithSecretKey(
  data: Uint8Array,
  key: SecretKey,
  aad?: Uint8Array | null
): Uint8Array;
```

---

## Phase 4 — UniFFI (Kotlin + Swift)

### Files
- `uniffi/devolutions-crypto-uniffi/src/key.rs`
- `uniffi/devolutions-crypto-uniffi/src/ciphertext.rs`

Kotlin and Swift bindings are auto-generated by UniFFI at build time. Editing these two Rust files is all that is needed.

### Changes

**`uniffi/devolutions-crypto-uniffi/src/key.rs`**

Add `generate_secret_key` export (key is returned as serialized `Vec<u8>`, matching the byte-array convention used for `generate_keypair`):
```rust
#[uniffi::export(default(version = None))]
pub fn generate_secret_key(version: Option<KeyVersion>) -> Vec<u8> {
    let version = version.unwrap_or(KeyVersion::Latest);
    devolutions_crypto::key::generate_secret_key(version).into()
}
```

**`uniffi/devolutions-crypto-uniffi/src/ciphertext.rs`**

Add four functions following the exact `encrypt_asymmetric`/`decrypt_asymmetric` pattern (deserialize key, delegate):

```rust
#[uniffi::export(default(version = None))]
pub fn encrypt_with_secret_key(
    data: &[u8],
    key: &[u8],
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>> {
    let version = version.unwrap_or(CiphertextVersion::Latest);
    let key = devolutions_crypto::key::SecretKey::try_from(key)?;
    Ok(devolutions_crypto::ciphertext::encrypt_with_secret_key(data, &key, version)?.into())
}

#[uniffi::export(default(version = None))]
pub fn encrypt_with_secret_key_and_aad(
    data: &[u8],
    key: &[u8],
    aad: &[u8],
    version: Option<CiphertextVersion>,
) -> Result<Vec<u8>> {
    let version = version.unwrap_or(CiphertextVersion::Latest);
    let key = devolutions_crypto::key::SecretKey::try_from(key)?;
    Ok(devolutions_crypto::ciphertext::encrypt_with_secret_key_and_aad(data, &key, aad, version)?.into())
}

#[uniffi::export]
pub fn decrypt_with_secret_key(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let key = devolutions_crypto::key::SecretKey::try_from(key)?;
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data)?;
    data.decrypt_with_secret_key(&key)
}

#[uniffi::export]
pub fn decrypt_with_secret_key_and_aad(data: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = devolutions_crypto::key::SecretKey::try_from(key)?;
    let data = devolutions_crypto::ciphertext::Ciphertext::try_from(data)?;
    data.decrypt_with_secret_key_and_aad(&key, aad)
}
```

Also add `use devolutions_crypto::key::SecretKey;` to the imports at the top of `ciphertext.rs`.

### Resulting generated Kotlin surface
```kotlin
fun generateSecretKey(version: KeyVersion? = null): ByteArray
fun encryptWithSecretKey(data: ByteArray, key: ByteArray, version: CiphertextVersion? = null): ByteArray
fun encryptWithSecretKeyAndAad(data: ByteArray, key: ByteArray, aad: ByteArray, version: CiphertextVersion? = null): ByteArray
fun decryptWithSecretKey(data: ByteArray, key: ByteArray): ByteArray
fun decryptWithSecretKeyAndAad(data: ByteArray, key: ByteArray, aad: ByteArray): ByteArray
```

### Resulting generated Swift surface
```swift
public func generateSecretKey(version: KeyVersion? = nil) -> Data
public func encryptWithSecretKey(data: Data, key: Data, version: CiphertextVersion? = nil) throws -> Data
public func encryptWithSecretKeyAndAad(data: Data, key: Data, aad: Data, version: CiphertextVersion? = nil) throws -> Data
public func decryptWithSecretKey(data: Data, key: Data) throws -> Data
public func decryptWithSecretKeyAndAad(data: Data, key: Data, aad: Data) throws -> Data
```

### Tests

**Kotlin** (`wrappers/kotlin/lib/src/test/kotlin/org/devolutions/crypto/SymmetricTest.kt`):
- `testGenerateSecretKeyAndEncryptDecrypt` — generate, encrypt, decrypt, assert equality.
- `testEncryptDecryptWithSecretKeyAndAad` — same with AAD; wrong AAD returns error.

**Swift** (`wrappers/swift/DevolutionsCryptoSwift/Tests/DevolutionsCryptoSwiftTests/SymmetricTests.swift`):
- `testGenerateSecretKeyAndEncryptDecrypt` — generate, encrypt, decrypt, assert equality.
- `testEncryptDecryptWithSecretKeyAndAad` — same with AAD; wrong AAD throws.

---

## Phase 5 — Python

### Files
- `python/src/lib.rs`
- `python/devolutions_crypto.pyi`

### Changes

**`python/src/lib.rs`**

1. Add `use devolutions_crypto::key::{SecretKey, generate_secret_key as dc_generate_secret_key, KeyVersion as DcKeyVersion};` (or adjust existing imports).

2. Add `generate_secret_key`:
   ```rust
   #[pyfunction]
   #[pyo3(signature = (version=0))]
   fn generate_secret_key(py: Python, version: u16) -> Result<Py<PyBytes>> {
       let version = DcKeyVersion::try_from(version)?;
       let key = dc_generate_secret_key(version);
       let bytes: Vec<u8> = key.into();
       Ok(PyBytes::new(py, &bytes).into())
   }
   ```

3. Add `encrypt_with_secret_key`:
   ```rust
   #[pyfunction]
   #[pyo3(signature = (data, key, aad=None, version=0))]
   fn encrypt_with_secret_key(
       py: Python,
       data: &[u8],
       key: &[u8],
       aad: Option<&[u8]>,
       version: u16,
   ) -> Result<Py<PyBytes>> {
       let version = CiphertextVersion::try_from(version)?;
       let key = SecretKey::try_from(key)?;
       let aad = aad.unwrap_or(&[]);
       let ct = devolutions_crypto::ciphertext::encrypt_with_secret_key_and_aad(data, &key, aad, version)?;
       Ok(PyBytes::new(py, &Into::<Vec<u8>>::into(ct)).into())
   }
   ```

4. Add `decrypt_with_secret_key`:
   ```rust
   #[pyfunction]
   #[pyo3(signature = (data, key, aad=None))]
   fn decrypt_with_secret_key(
       py: Python,
       data: &[u8],
       key: &[u8],
       aad: Option<&[u8]>,
   ) -> Result<Py<PyBytes>> {
       let key = SecretKey::try_from(key)?;
       let aad = aad.unwrap_or(&[]);
       let ct = devolutions_crypto::ciphertext::Ciphertext::try_from(data)?;
       let plaintext = ct.decrypt_with_secret_key_and_aad(&key, aad)?;
       Ok(PyBytes::new(py, &plaintext).into())
   }
   ```

5. **Register all three** in the `#[pymodule]` function:
   ```rust
   m.add_function(wrap_pyfunction!(generate_secret_key, m)?)?;
   m.add_function(wrap_pyfunction!(encrypt_with_secret_key, m)?)?;
   m.add_function(wrap_pyfunction!(decrypt_with_secret_key, m)?)?;
   ```

**`python/devolutions_crypto.pyi`** — add stubs:
```python
def generate_secret_key(version: int = 0) -> bytes: ...
def encrypt_with_secret_key(data: bytes, key: bytes, aad: bytes | None = None, version: int = 0) -> bytes: ...
def decrypt_with_secret_key(data: bytes, key: bytes, aad: bytes | None = None) -> bytes: ...
```

### Tests (inline in `python/src/lib.rs` or in a Python test file)
- Generate a secret key, encrypt, decrypt, assert equality.
- Wrong key returns error. Wrong AAD returns error.

---

## Relevant files summary

| File | Change |
|------|--------|
| `ffi/src/lib.rs` | Add `GenerateSecretKey`, `GenerateSecretKeySize` |
| `ffi/devolutions-crypto.h` | Add C declarations for the two new FFI functions |
| `wrappers/csharp/src/Native.Core.cs` | Add `GenerateSecretKeyNative`, `GenerateSecretKeySizeNative` P/Invoke |
| `wrappers/csharp/src/Managed.cs` | Add `GenerateSecretKey() -> byte[]` |
| `src/wasm.rs` | Add `SecretKey` wasm impls, `generateSecretKey`, `encryptWithSecretKey`, `decryptWithSecretKey` |
| `uniffi/devolutions-crypto-uniffi/src/key.rs` | Add `generate_secret_key` export |
| `uniffi/devolutions-crypto-uniffi/src/ciphertext.rs` | Add four `*_with_secret_key` exports |
| `python/src/lib.rs` | Add `generate_secret_key`, `encrypt_with_secret_key`, `decrypt_with_secret_key` |
| `python/devolutions_crypto.pyi` | Add three stubs |

---

## Verification

1. `cargo check` — no errors across all crates (ffi, python, uniffi, main with wbindgen feature).
2. `cargo test` — all tests pass.
3. C#: `dotnet test` in `wrappers/csharp/`.
4. WASM: rebuild with `wasm-pack build` and run the JS/TS tests.
5. Kotlin: `./gradlew test` in `wrappers/kotlin/`.
6. Swift: `swift test` in `wrappers/swift/DevolutionsCryptoSwift/`.
7. Python: `maturin develop` + `pytest`.

## Decisions

- **FFI returns the full serialized `SecretKey` blob** (header + 32 bytes), not just the raw 32 bytes. This is consistent with how `GenerateKeyPair` returns serialized key blobs, and means callers can pass the result directly to the existing `Encrypt`/`Decrypt` byte-array functions.
- **C# and Python return `byte[]`/`bytes`**, not dedicated wrapper types — consistent with how asymmetric keys are handled in those wrappers.
- **WASM gets a first-class `SecretKey` class** with `bytes`/`fromBytes` — consistent with `PrivateKey`/`PublicKey` in that wrapper.
- **UniFFI (Kotlin/Swift) uses serialized bytes** — consistent with the `encrypt_asymmetric` pattern where keys are passed as `&[u8]` and deserialized inside.
- **No new `EncryptWithSecretKey`/`DecryptWithSecretKey` in the FFI layer** — the existing `Encrypt`/`Decrypt` already accept the key as a raw byte buffer, and callers can pass the payload of a `SecretKey`. A typed variant adds no functionality at the C ABI level.
