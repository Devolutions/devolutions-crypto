import { hashPassword, verifyPassword } from 'devolutions-crypto'
import { expect } from 'chai'
import { describe, it } from 'mocha'

const encoder: TextEncoder = new TextEncoder()

describe('hashing', () => {
  it('should validate the password', () => {
    const hash: Uint8Array = hashPassword(encoder.encode('password'), 10)

    expect(verifyPassword(encoder.encode('password'), hash)).to.eql(true)
  })

  it('should not validate the password', () => {
    const hash: Uint8Array = hashPassword(encoder.encode('password'), 10)

    expect(verifyPassword(encoder.encode('pa$$word'), hash)).to.eql(false)
    expect(verifyPassword(encoder.encode('Password'), hash)).to.eql(false)
    expect(verifyPassword(encoder.encode('password1'), hash)).to.eql(false)
  })
})
