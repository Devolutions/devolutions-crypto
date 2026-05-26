import { deriveSecretKeyPbkdf2, deriveSecretKeyArgon2, Argon2Parameters, DerivationParameters, KeyDerivationResult, base64encode, base64decode } from 'devolutions-crypto'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

const encoder: TextEncoder = new TextEncoder()

describe('key derivation', () => {
  test('deriveSecretKeyPbkdf2 returns a secret key and parameters', () => {
    const result: KeyDerivationResult = deriveSecretKeyPbkdf2(encoder.encode('test password'), 10)

    assert.ok(result.secretKey.bytes.length > 0)
    assert.ok(result.parameters.bytes.length > 0)
  })

  test('deriveSecretKeyPbkdf2 produces different results for each call (random salt)', () => {
    const password = encoder.encode('same password')

    const result1: KeyDerivationResult = deriveSecretKeyPbkdf2(password, 10)
    const result2: KeyDerivationResult = deriveSecretKeyPbkdf2(password, 10)

    // Random salt → different parameters and different derived keys
    assert.notStrictEqual(base64encode(result1.parameters.bytes), base64encode(result2.parameters.bytes))
    assert.notStrictEqual(base64encode(result1.secretKey.bytes), base64encode(result2.secretKey.bytes))
  })

  test('deriveSecretKeyArgon2 with fixed parameters produces the same key', () => {
    const password = encoder.encode('test password')
    const fixedParams: Argon2Parameters = Argon2Parameters.fromBytes(
      base64decode('AQAAACAAAAABAAAAIAAAAAEAAAACEwAAAAAQAAAAimFBkm3f8+f+YfLRnF5OoQ==')
    )

    const result1: KeyDerivationResult = deriveSecretKeyArgon2(password, fixedParams)
    const result2: KeyDerivationResult = deriveSecretKeyArgon2(password, fixedParams)

    // Same parameters (same salt) + same password → same derived key
    assert.strictEqual(base64encode(result1.secretKey.bytes), base64encode(result2.secretKey.bytes))
  })

  test('deriveSecretKeyArgon2 with default parameters produces different results (random salt)', () => {
    const password = encoder.encode('test password')

    const result1: KeyDerivationResult = deriveSecretKeyArgon2(password, new Argon2Parameters())
    const result2: KeyDerivationResult = deriveSecretKeyArgon2(password, new Argon2Parameters())

    assert.notStrictEqual(base64encode(result1.secretKey.bytes), base64encode(result2.secretKey.bytes))
    assert.notStrictEqual(base64encode(result1.parameters.bytes), base64encode(result2.parameters.bytes))
  })

  test('DerivationParameters round-trip through bytes', () => {
    const result: KeyDerivationResult = deriveSecretKeyPbkdf2(encoder.encode('round trip'), 10)

    const paramsBytes = result.parameters.bytes
    const restored: DerivationParameters = DerivationParameters.fromBytes(paramsBytes)

    assert.strictEqual(base64encode(restored.bytes), base64encode(paramsBytes))
  })
})
