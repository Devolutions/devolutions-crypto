import { hashPassword, verifyPassword } from 'devolutions-crypto'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

const encoder: TextEncoder = new TextEncoder()

describe('hashing', () => {
  test('should validate the password', () => {
    const hash: Uint8Array = hashPassword(encoder.encode('password'), 10)

    assert.strictEqual(verifyPassword(encoder.encode('password'), hash), true)
  })

  test('should not validate the password', () => {
    const hash: Uint8Array = hashPassword(encoder.encode('password'), 10)

    assert.strictEqual(verifyPassword(encoder.encode('pa$$word'), hash), false)
    assert.strictEqual(verifyPassword(encoder.encode('Password'), hash), false)
    assert.strictEqual(verifyPassword(encoder.encode('password1'), hash), false)
  })
})
