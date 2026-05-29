import { hashPassword, hashPasswordWithParams, verifyPassword, getPbkdf2DerivationParameters, getArgon2DerivationParameters, Argon2Parameters } from 'devolutions-crypto'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

const encoder: TextEncoder = new TextEncoder()

describe('hashing', () => {
  test('should validate the password using hashPassword', () => {
    const password = encoder.encode('password')
    const hash: Uint8Array = hashPassword(password)

    assert.strictEqual(verifyPassword(password, hash), true)
    assert.strictEqual(verifyPassword(encoder.encode('wrong'), hash), false)
  })

  test('should validate the password with custom PBKDF2 params (fast)', () => {
    // Use PBKDF2 with low iterations for test speed
    const params: Uint8Array = getPbkdf2DerivationParameters(10)
    const hash: Uint8Array = hashPasswordWithParams(encoder.encode('password'), params)

    assert.strictEqual(verifyPassword(encoder.encode('password'), hash), true)
  })

  test('should not validate the password with invalid hash', () => {
    const params: Uint8Array = getPbkdf2DerivationParameters(10)
    const hash: Uint8Array = hashPasswordWithParams(encoder.encode('password'), params)

    assert.strictEqual(verifyPassword(encoder.encode('pa$$word'), hash), false)
    assert.strictEqual(verifyPassword(encoder.encode('Password'), hash), false)
    assert.strictEqual(verifyPassword(encoder.encode('password1'), hash), false)
  })

  test('should validate the password with custom Argon2 params (memory=32, iterations=2)', () => {
    const argon2Params = new Argon2Parameters()
    argon2Params.memory = 32
    argon2Params.iterations = 2
    const params: Uint8Array = getArgon2DerivationParameters(argon2Params)
    const hash: Uint8Array = hashPasswordWithParams(encoder.encode('password'), params)

    assert.strictEqual(verifyPassword(encoder.encode('password'), hash), true)
    assert.strictEqual(verifyPassword(encoder.encode('wrong'), hash), false)
  })
})
