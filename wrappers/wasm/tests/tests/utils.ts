import { generateKey, deriveKeyPbkdf2, validateHeader, base64encode, base64decode, base64urlEncode, base64urlDecode, DataType, Argon2Parameters, deriveKeyArgon2 } from 'devolutions-crypto'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

const encoder: TextEncoder = new TextEncoder()
const decoder: TextDecoder = new TextDecoder()

describe('generateKey', () => {
  test('should return a 32 bytes random key by default', () => {
    const result: Uint8Array = generateKey()
    assert.strictEqual(result.length, 32)
    assert.notDeepStrictEqual(result, new Uint8Array(32))
  })

  test('should return a 41 bytes random key', () => {
    const result: Uint8Array = generateKey(41)
    assert.strictEqual(result.length, 41)
    assert.notDeepStrictEqual(result, new Uint8Array(41))
  })

  test('should return different keys', () => {
    const result1: Uint8Array = generateKey()
    const result2: Uint8Array = generateKey()
    assert.notDeepStrictEqual(result1, result2)
  })
})

describe('deriveKeyPbkdf2', () => {
  test('should derive a key of 32 bytes', () => {
    const result: Uint8Array = deriveKeyPbkdf2(encoder.encode('password'), null, 10)
    assert.strictEqual(result.length, 32)
    assert.notDeepStrictEqual(result, new Uint8Array(32))
  })

  test('should derive a key of 41 bytes', () => {
    const result: Uint8Array = deriveKeyPbkdf2(encoder.encode('password'), null, 10, 41)
    assert.strictEqual(result.length, 41)
    assert.notDeepStrictEqual(result, new Uint8Array(41))
  })

  test('should produce the same key', () => {
    const result1: Uint8Array = deriveKeyPbkdf2(encoder.encode('password'), null, 10)
    const result2: Uint8Array = deriveKeyPbkdf2(encoder.encode('password'), null, 10)
    assert.strictEqual(result1.length, 32)
    assert.notDeepStrictEqual(result1, new Uint8Array(41))
    assert.deepStrictEqual(result1, result2)
  })

  test('should produce different keys', () => {
    const result: Uint8Array = deriveKeyPbkdf2(encoder.encode('password'), encoder.encode('thisisasalt'), 10)
    const differentPass: Uint8Array = deriveKeyPbkdf2(encoder.encode('pa$$word'), encoder.encode('thisisasalt'), 10)
    const differentSalt: Uint8Array = deriveKeyPbkdf2(encoder.encode('password'), encoder.encode('this1sasalt'), 10)
    const differentIterations: Uint8Array = deriveKeyPbkdf2(encoder.encode('password'), encoder.encode('thisisasalt'), 11)

    assert.notDeepStrictEqual(result, differentPass)
    assert.notDeepStrictEqual(result, differentSalt)
    assert.notDeepStrictEqual(result, differentIterations)
  })
})

describe('deriveKeyArgon2', () => {
  test('should derive a key of 32 bytes', () => {
    const parameters: Argon2Parameters = new Argon2Parameters()
    const result: Uint8Array = deriveKeyArgon2(encoder.encode('password'), parameters)
    assert.strictEqual(result.length, 32)
    assert.notDeepStrictEqual(result, new Uint8Array(32))
  })
})

describe('validateHeader', () => {
  test('should return true', () => {
    const validCiphertext: Uint8Array = base64decode('DQwCAAAAAQA=')
    const validPasswordHash: Uint8Array = base64decode('DQwDAAAAAQA=')
    const validShare: Uint8Array = base64decode('DQwEAAAAAQA=')
    const validPrivateKey: Uint8Array = base64decode('DQwBAAEAAQA=')
    const validPublicKey: Uint8Array = base64decode('DQwBAAEAAQA=')

    assert.strictEqual(validateHeader(validCiphertext, DataType.Ciphertext), true)
    assert.strictEqual(validateHeader(validPasswordHash, DataType.PasswordHash), true)
    assert.strictEqual(validateHeader(validShare, DataType.Share), true)
    assert.strictEqual(validateHeader(validPrivateKey, DataType.Key), true)
    assert.strictEqual(validateHeader(validPublicKey, DataType.Key), true)
  })

  test('should return false', () => {
    const validCiphertext: Uint8Array = base64decode('DQwCAAAAAQA=')

    assert.strictEqual(validateHeader(validCiphertext, DataType.PasswordHash), false)

    const invalidSignature: Uint8Array = base64decode('DAwBAAEAAQA=')
    const invalidType: Uint8Array = base64decode('DQwIAAEAAQA=')
    const invalidSubtype: Uint8Array = base64decode('DQwBAAgAAQA=')
    const invalidVersion: Uint8Array = base64decode('DQwBAAEACAA=')

    assert.strictEqual(validateHeader(invalidSignature, DataType.Key), false)
    assert.strictEqual(validateHeader(invalidType, DataType.Key), false)
    assert.strictEqual(validateHeader(invalidSubtype, DataType.Key), false)
    assert.strictEqual(validateHeader(invalidVersion, DataType.Key), false)

    const notLongEnough: Uint8Array = base64decode('DQwBAAEAAQ==')

    assert.strictEqual(validateHeader(notLongEnough, DataType.Key), false)
  })
})

describe('base64', () => {
  test('should give the right encoded value', () => {
    const input: Uint8Array = Uint8Array.from([0x41, 0x42, 0x43, 0x44, 0x45])
    const result: string = base64encode(input)
    assert.strictEqual(result, 'QUJDREU=')
  })

  test('should give the right decoded value', () => {
    const input: string = 'YWJjZGU='
    const result: Uint8Array = base64decode(input)
    assert.deepStrictEqual(result, Uint8Array.from([0x61, 0x62, 0x63, 0x64, 0x65]))
  })
})

describe('base64url', () => {
  test('should give the right encoded value', () => {
    const input1: Uint8Array = encoder.encode('Ab6/')
    const result1: string = base64urlEncode(input1)
    assert.strictEqual(result1, 'QWI2Lw')

    const input2: Uint8Array = encoder.encode('Ab6/75')
    const result2: string = base64urlEncode(input2)
    assert.strictEqual(result2, 'QWI2Lzc1')

    const input3: Uint8Array = Uint8Array.from([0xff, 0xff, 0xfe, 0xff])
    const result3: string = base64urlEncode(input3)
    assert.strictEqual(result3, '___-_w')
  })

  test('should give the right decoded value', () => {
    const input1: string = 'QWI2Lw'
    const result1: string = decoder.decode(base64urlDecode(input1))
    assert.strictEqual(result1, 'Ab6/')

    const input2: string = 'QWI2Lzc1'
    const result2: string = decoder.decode(base64urlDecode(input2))
    assert.strictEqual(result2, 'Ab6/75')

    const input3: string = '___-_w'
    const result3: Uint8Array = base64urlDecode(input3)
    assert.deepStrictEqual(result3, Uint8Array.from([0xff, 0xff, 0xfe, 0xff]))
  })
})
