import { generateKey, deriveKey, base64encode, base64decode } from 'devolutions-crypto'
import { expect } from 'chai'
import { describe, it } from 'mocha'

const encoder: TextEncoder = new TextEncoder()

describe('generateKey', () => {
  it('should return a 32 bytes random key by default', () => {
    const result: Uint8Array = generateKey()
    expect(result).to.have.lengthOf(32)
    expect(result).to.not.eql(new Array(32).fill(0))
  })

  it('should return a 41 bytes random key', () => {
    const result: Uint8Array = generateKey(41)
    expect(result).to.have.lengthOf(41)
    expect(result).to.not.eql(new Array(41).fill(0))
  })

  it('should return different keys', () => {
    const result1: Uint8Array = generateKey()
    const result2: Uint8Array = generateKey()
    expect(result1).to.not.eql(result2)
  })
})

describe('deriveKey', () => {
  it('should derive a key of 32 bytes', () => {
    const result: Uint8Array = deriveKey(encoder.encode('password'), null, 10)
    expect(result).to.have.lengthOf(32)
    expect(result).to.not.eql(new Array(32).fill(0))
  })

  it('should derive a key of 41 bytes', () => {
    const result: Uint8Array = deriveKey(encoder.encode('password'), null, 10, 41)
    expect(result).to.have.lengthOf(41)
    expect(result).to.not.eql(new Array(41).fill(0))
  })

  it('should produce the same key', () => {
    const result1: Uint8Array = deriveKey(encoder.encode('password'), null, 10)
    const result2: Uint8Array = deriveKey(encoder.encode('password'), null, 10)
    expect(result1).to.have.lengthOf(32)
    expect(result1).to.not.eql(new Array(41).fill(0))
    expect(result2).to.eql(result2)
  })

  it('should produce different keys', () => {
    const result: Uint8Array = deriveKey(encoder.encode('password'), encoder.encode('thisisasalt'), 10)
    const differentPass: Uint8Array = deriveKey(encoder.encode('pa$$word'), encoder.encode('thisisasalt'), 10)
    const differentSalt: Uint8Array = deriveKey(encoder.encode('password'), encoder.encode('this1sasalt'), 10)
    const differentIterations: Uint8Array = deriveKey(encoder.encode('password'), encoder.encode('thisisasalt'), 11)

    expect(result).to.not.eql(differentPass)
    expect(result).to.not.eql(differentSalt)
    expect(result).to.not.eql(differentIterations)
  })
})

describe('base64', () => {
  it('should give the right encoded value', () => {
    const input: Uint8Array = Uint8Array.from([0x41, 0x42, 0x43, 0x44, 0x45])
    const result: string = base64encode(input)
    expect(result).to.eql('QUJDREU=')
  })

  it('should give the right decoded value', () => {
    const input: string = 'YWJjZGU='
    const result: Uint8Array = base64decode(input)
    expect(result).to.eql(Uint8Array.from([0x61, 0x62, 0x63, 0x64, 0x65]))
  })
})
