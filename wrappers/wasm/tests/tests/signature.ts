import { generateSigningKeyPair, sign, verifySignature } from 'devolutions-crypto'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

const encoder: TextEncoder = new TextEncoder()

describe('signature', () => {
  test('should validate the signature', () => {
    const data = encoder.encode("this is a test")
    const keypair = generateSigningKeyPair()

    const signature = sign(data, keypair)

    assert.strictEqual(verifySignature(data, keypair.public, signature), true)
  })

  test('should not validate the password', () => {
    const keypair = generateSigningKeyPair()

    const signature = sign(encoder.encode("this is test data"), keypair)

    assert.strictEqual(verifySignature(encoder.encode("this is wrong data"), keypair.public, signature), false)
  })
})
