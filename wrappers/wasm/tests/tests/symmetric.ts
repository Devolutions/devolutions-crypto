import { generateKey, encrypt, decrypt } from 'devolutions-crypto'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

const encoder: TextEncoder = new TextEncoder()

describe('encrypt/decrypt', () => {
  test('should be able to encrypt and decrypt', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const key: Uint8Array = generateKey()
    const encrypted: Uint8Array = encrypt(input, key)
    const decrypted: Uint8Array = decrypt(encrypted, key)
    assert.notDeepStrictEqual(encrypted, input)
    assert.deepStrictEqual(decrypted, input)
  })

  test('should be able to encrypt and decrypt with an AAD', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const aad: Uint8Array = encoder.encode('This is some public data')
    const key: Uint8Array = generateKey()
    const encrypted: Uint8Array = encrypt(input, key, aad)
    const decrypted: Uint8Array = decrypt(encrypted, key, aad)
    assert.notDeepStrictEqual(encrypted, input)
    assert.deepStrictEqual(decrypted, input)
  })

  test('should fail if AAD is invalid', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const aad: Uint8Array = encoder.encode('This is some public data')
    const wrongAad: Uint8Array = encoder.encode('this is some public data')
    const key: Uint8Array = generateKey()
    const encrypted: Uint8Array = encrypt(input, key, aad)

    assert.throws(() => decrypt(encrypted, key))
    assert.throws(() => decrypt(encrypted, key, wrongAad))
  })
})
