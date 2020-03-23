import { generateKey, deriveKey, validateSignature, base64encode, base64decode, DataType } from 'devolutions-crypto'
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

describe('validateSignature', () => {
  it('should return true', () => {
    const validCiphertext: Uint8Array = base64decode('DQwCAAAAAQA=')
    const validPasswordHash: Uint8Array = base64decode('DQwDAAAAAQA=')
    const validShare: Uint8Array = base64decode('DQwEAAAAAQA=')
    const validPrivateKey: Uint8Array = base64decode('DQwBAAEAAQA=')
    const validPublicKey: Uint8Array = base64decode('DQwBAAEAAQA=')

    expect(validateSignature(validCiphertext, DataType.Ciphertext)).to.eql(true)
    expect(validateSignature(validPasswordHash, DataType.PasswordHash)).to.eql(true)
    expect(validateSignature(validShare, DataType.Share)).to.eql(true)
    expect(validateSignature(validPrivateKey, DataType.Key)).to.eql(true)
    expect(validateSignature(validPublicKey, DataType.Key)).to.eql(true)
  })

  it('should return false', () => {
    const validCiphertext: Uint8Array = base64decode('DQwCAAAAAQA=')

    expect(validateSignature(validCiphertext, DataType.PasswordHash)).to.eql(false)

    const invalidSignature: Uint8Array = base64decode('DAwBAAEAAQA=')
    const invalidType: Uint8Array = base64decode('DQwIAAEAAQA=')
    const invalidSubtype: Uint8Array = base64decode('DQwBAAgAAQA=')
    const invalidVersion: Uint8Array = base64decode('DQwBAAEACAA=')

    expect(validateSignature(invalidSignature, DataType.Key)).to.eql(false)
    expect(validateSignature(invalidType, DataType.Key)).to.eql(false)
    expect(validateSignature(invalidSubtype, DataType.Key)).to.eql(false)
    expect(validateSignature(invalidVersion, DataType.Key)).to.eql(false)

    const notLongEnough: Uint8Array = base64decode('DQwBAAEAAQ==')

    expect(validateSignature(notLongEnough, DataType.Key)).to.eql(false)
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
