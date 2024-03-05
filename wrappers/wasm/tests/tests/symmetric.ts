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

  it('should be able to encrypt and decrypt with an AAD', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const aad: Uint8Array = encoder.encode('This is some public data')
    const key: Uint8Array = generateKey()
    const encrypted: Uint8Array = encrypt(input, key, aad)
    const decrypted: Uint8Array = decrypt(encrypted, key, aad)
    expect(encrypted).to.not.contains(input)
    expect(decrypted).to.eql(input)
  })

  it('should fail if AAD is invalid', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const aad: Uint8Array = encoder.encode('This is some public data')
    const wrongAad: Uint8Array = encoder.encode('this is some public data')
    const key: Uint8Array = generateKey()
    const encrypted: Uint8Array = encrypt(input, key, aad)

    expect(() => decrypt(encrypted, key)).to.throw()
    expect(() => decrypt(encrypted, key, wrongAad)).to.throw()
  })
})
