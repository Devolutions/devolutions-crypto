import { generateSigningKeyPair, sign, verifySignature } from 'devolutions-crypto'
import { expect } from 'chai'
import { describe, it } from 'mocha'

const encoder: TextEncoder = new TextEncoder()

describe('signature', () => {
  it('should validate the signature', () => {
    const data = encoder.encode("this is a test")
    const keypair = generateSigningKeyPair()

    const signature = sign(data, keypair)

    expect(verifySignature(data, keypair.public, signature)).to.eql(true)
  })

  it('should not validate the password', () => {
    const keypair = generateSigningKeyPair()

    const signature = sign(encoder.encode("this is test data"), keypair)

    expect(verifySignature(encoder.encode("this is wrong data"), keypair.public, signature)).to.eql(false)
  })
})
