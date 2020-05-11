import { generateKey, deriveKey, validateHeader, base64encode, base64decode, base64urlEncode, base64urlDecode, DataType } from 'devolutions-crypto'
import { expect } from 'chai'
import { describe, it } from 'mocha'

const encoder: TextEncoder = new TextEncoder()
const decoder: TextDecoder = new TextDecoder()

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

    expect(validateHeader(validCiphertext, DataType.Ciphertext)).to.eql(true)
    expect(validateHeader(validPasswordHash, DataType.PasswordHash)).to.eql(true)
    expect(validateHeader(validShare, DataType.Share)).to.eql(true)
    expect(validateHeader(validPrivateKey, DataType.Key)).to.eql(true)
    expect(validateHeader(validPublicKey, DataType.Key)).to.eql(true)
  })

  it('should return false', () => {
    const validCiphertext: Uint8Array = base64decode('DQwCAAAAAQA=')

    expect(validateHeader(validCiphertext, DataType.PasswordHash)).to.eql(false)

    const invalidSignature: Uint8Array = base64decode('DAwBAAEAAQA=')
    const invalidType: Uint8Array = base64decode('DQwIAAEAAQA=')
    const invalidSubtype: Uint8Array = base64decode('DQwBAAgAAQA=')
    const invalidVersion: Uint8Array = base64decode('DQwBAAEACAA=')

    expect(validateHeader(invalidSignature, DataType.Key)).to.eql(false)
    expect(validateHeader(invalidType, DataType.Key)).to.eql(false)
    expect(validateHeader(invalidSubtype, DataType.Key)).to.eql(false)
    expect(validateHeader(invalidVersion, DataType.Key)).to.eql(false)

    const notLongEnough: Uint8Array = base64decode('DQwBAAEAAQ==')

    expect(validateHeader(notLongEnough, DataType.Key)).to.eql(false)
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

describe('base64url', () => {
  it('should give the right encoded value', () => {
    const input1: Uint8Array = encoder.encode('Ab6/')
    const result1: string = base64urlEncode(input1)
    expect(result1).to.eql('QWI2Lw')

    const input2: Uint8Array = encoder.encode('Ab6/75')
    const result2: string = base64urlEncode(input2)
    expect(result2).to.eql('QWI2Lzc1')

    const input3: Uint8Array = Uint8Array.from([0xff, 0xff, 0xfe, 0xff])
    const result3: string = base64urlEncode(input3)
    expect(result3).to.eql('___-_w')
  })

  it('should give the right decoded value', () => {
    const input1: string = 'QWI2Lw'
    const result1: string = decoder.decode(base64urlDecode(input1))
    expect(result1).to.eql('Ab6/')

    const input2: string = 'QWI2Lzc1'
    const result2: string = decoder.decode(base64urlDecode(input2))
    expect(result2).to.eql('Ab6/75')

    const input3: string = '___-_w'
    const result3: Uint8Array = base64urlDecode(input3)
    expect(result3).to.eql(Uint8Array.from([0xff, 0xff, 0xfe, 0xff]))
  })
})
