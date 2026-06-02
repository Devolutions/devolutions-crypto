import {
  deriveEncryptWithPassword,
  deriveDecryptWithPassword,
  deriveSecretKeyPbkdf2WithSalt,
  deriveSecretKeyArgon2,
  Argon2Parameters,
  DerivationParameters,
  base64encode,
  base64decode,
} from 'devolutions-crypto'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

const encoder: TextEncoder = new TextEncoder()

describe('derive encrypt/decrypt', () => {
  test('roundtrip with password', () => {
    const plaintext = encoder.encode('hello world')
    const password = encoder.encode('mypassword')

    const blob = deriveEncryptWithPassword(plaintext, password)
    const decrypted = deriveDecryptWithPassword(blob, password)

    assert.deepStrictEqual(decrypted, plaintext)
  })

  test('encrypted blob differs from plaintext', () => {
    const plaintext = encoder.encode('sensitive data')
    const password = encoder.encode('password123')

    const blob = deriveEncryptWithPassword(plaintext, password)

    assert.notDeepStrictEqual(blob, plaintext)
  })

  test('each encryption produces a different blob (random salt)', () => {
    const plaintext = encoder.encode('same data')
    const password = encoder.encode('same password')

    const blob1 = deriveEncryptWithPassword(plaintext, password)
    const blob2 = deriveEncryptWithPassword(plaintext, password)

    assert.notStrictEqual(base64encode(blob1), base64encode(blob2))
  })

  test('wrong password fails to decrypt', () => {
    const plaintext = encoder.encode('secret')
    const password = encoder.encode('correct-password')

    const blob = deriveEncryptWithPassword(plaintext, password)

    assert.throws(() => {
      deriveDecryptWithPassword(blob, encoder.encode('wrong-password'))
    })
  })

  test('roundtrip with aad', () => {
    const plaintext = encoder.encode('authenticated data')
    const password = encoder.encode('mypassword')
    const aad = encoder.encode('context')

    const blob = deriveEncryptWithPassword(plaintext, password, aad)
    const decrypted = deriveDecryptWithPassword(blob, password, aad)

    assert.deepStrictEqual(decrypted, plaintext)
  })

  test('wrong aad fails to decrypt', () => {
    const plaintext = encoder.encode('authenticated data')
    const password = encoder.encode('mypassword')
    const aad = encoder.encode('context')

    const blob = deriveEncryptWithPassword(plaintext, password, aad)

    assert.throws(() => {
      deriveDecryptWithPassword(blob, password, encoder.encode('wrong-context'))
    })
  })

  test('aad-encrypted blob cannot be decrypted without aad', () => {
    const plaintext = encoder.encode('authenticated data')
    const password = encoder.encode('mypassword')
    const aad = encoder.encode('context')

    const blob = deriveEncryptWithPassword(plaintext, password, aad)

    assert.throws(() => {
      deriveDecryptWithPassword(blob, password)
    })
  })

  test('roundtrip with explicit Argon2 DerivationParameters', () => {
    const plaintext = encoder.encode('hello world')
    const password = encoder.encode('mypassword')
    const { parameters } = deriveSecretKeyArgon2(password, new Argon2Parameters())

    const blob = deriveEncryptWithPassword(plaintext, password, undefined, parameters)
    const decrypted = deriveDecryptWithPassword(blob, password)

    assert.deepStrictEqual(decrypted, plaintext)
  })

  test('fixed Argon2 parameters produce different blobs (ciphertext nonce is random)', () => {
    const plaintext = encoder.encode('same data')
    const password = encoder.encode('same password')
    const { parameters } = deriveSecretKeyArgon2(password, new Argon2Parameters())

    const blob1 = deriveEncryptWithPassword(plaintext, password, undefined, parameters)
    const blob2 = deriveEncryptWithPassword(plaintext, password, undefined, parameters)

    assert.notStrictEqual(base64encode(blob1), base64encode(blob2))
  })

  test('roundtrip with explicit PBKDF2 DerivationParameters', () => {
    const plaintext = encoder.encode('hello world')
    const password = encoder.encode('mypassword')
    const salt = encoder.encode('fixed_salt_16byt')
    const { parameters } = deriveSecretKeyPbkdf2WithSalt(password, salt, 10)

    const blob = deriveEncryptWithPassword(plaintext, password, undefined, parameters)
    const decrypted = deriveDecryptWithPassword(blob, password)

    assert.deepStrictEqual(decrypted, plaintext)
  })

  test('roundtrip with explicit parameters and aad', () => {
    const plaintext = encoder.encode('secure payload')
    const password = encoder.encode('mypassword')
    const aad = encoder.encode('context')
    const { parameters } = deriveSecretKeyArgon2(password, new Argon2Parameters())

    const blob = deriveEncryptWithPassword(plaintext, password, aad, parameters)
    const decrypted = deriveDecryptWithPassword(blob, password, aad)

    assert.deepStrictEqual(decrypted, plaintext)
  })

  test('DerivationParameters round-trip through bytes when used with derive-encrypt', () => {
    const password = encoder.encode('mypassword')
    const { parameters } = deriveSecretKeyArgon2(password, new Argon2Parameters())

    const paramsBytes = parameters.bytes
    const restored: DerivationParameters = DerivationParameters.fromBytes(paramsBytes)

    const plaintext = encoder.encode('hello')
    const blob = deriveEncryptWithPassword(plaintext, password, undefined, restored)
    const decrypted = deriveDecryptWithPassword(blob, password)

    assert.deepStrictEqual(decrypted, plaintext)
  })
})

