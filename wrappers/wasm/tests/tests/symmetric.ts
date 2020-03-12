import { generateKey, encrypt, decrypt } from 'devolutions-crypto'
import { expect } from 'chai'
import { describe, it } from 'mocha'

const encoder: TextEncoder = new TextEncoder()

describe('encrypt/decrypt', () => {
  it('should be able to encrypt and decrypt', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const key: Uint8Array = generateKey()
    const encrypted: Uint8Array = encrypt(input, key)
    const decrypted: Uint8Array = decrypt(encrypted, key)
    expect(encrypted).to.not.contains(input)
    expect(decrypted).to.eql(input)
  })
})
