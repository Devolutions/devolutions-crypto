import {
  KeyPair, PublicKey, PrivateKey, Argon2Parameters,
  generateKey, generateKeyPair, encryptAsymmetric, decryptAsymmetric, mixKeyExchange
} from 'devolutions-crypto'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

const encoder: TextEncoder = new TextEncoder()

describe('generateKeyPair', () => {
  test('should generate a random keypair', () => {
    const keypair: KeyPair = generateKeyPair()
    assert.notStrictEqual(keypair.private.bytes.length, 0)
    assert.notStrictEqual(keypair.public.bytes.length, 0)
    assert.notDeepStrictEqual(keypair.private, keypair.public)
  })
})

describe('asymmetricEncrypt/asymmetricDecrypt', () => {
  test('should be able to encrypt and decrypt', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const keypair: KeyPair = generateKeyPair()
    const encrypted: Uint8Array = encryptAsymmetric(input, keypair.public)
    const decrypted: Uint8Array = decryptAsymmetric(encrypted, keypair.private)
    assert.notDeepStrictEqual(encrypted, input)
    assert.deepStrictEqual(decrypted, input)
  })

  test('should be able to encrypt and decrypt with an AAD', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const aad: Uint8Array = encoder.encode('This is some public data')
    const keypair: KeyPair = generateKeyPair()
    const encrypted: Uint8Array = encryptAsymmetric(input, keypair.public, aad)
    const decrypted: Uint8Array = decryptAsymmetric(encrypted, keypair.private, aad)
    assert.notDeepStrictEqual(encrypted, input)
    assert.deepStrictEqual(decrypted, input)
  })

  test('should fail if AAD is invalid', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const aad: Uint8Array = encoder.encode('This is some public data')
    const wrongAad: Uint8Array = encoder.encode('this is some public data')
    const keypair: KeyPair = generateKeyPair()
    const encrypted: Uint8Array = encryptAsymmetric(input, keypair.public, aad)

    assert.throws(() => decryptAsymmetric(encrypted, keypair.private))
    assert.throws(() => decryptAsymmetric(encrypted, keypair.private, wrongAad))
  })
})

describe('mixKeyExchange', () => {
  test('should give the same 32 byte shared key', () => {
    const bobKeyPair: KeyPair = generateKeyPair()
    const aliceKeyPair: KeyPair = generateKeyPair()

    const bobShared: Uint8Array = mixKeyExchange(bobKeyPair.private, aliceKeyPair.public)
    const aliceShared: Uint8Array = mixKeyExchange(aliceKeyPair.private, bobKeyPair.public)

    assert.strictEqual(bobShared.length, 32)
    assert.notDeepStrictEqual(bobShared, new Uint8Array(32))
    assert.deepStrictEqual(bobShared, aliceShared)
  })

  test('should not give the same 32 byte shared key', () => {
    const bobKeyPair: KeyPair = generateKeyPair()
    const aliceKeyPair: KeyPair = generateKeyPair()
    const eveKeyPair: KeyPair = generateKeyPair()

    const bobShared: Uint8Array = mixKeyExchange(bobKeyPair.private, aliceKeyPair.public)
    const aliceShared: Uint8Array = mixKeyExchange(aliceKeyPair.private, bobKeyPair.public)

    const eveBobShared: Uint8Array = mixKeyExchange(eveKeyPair.private, bobKeyPair.public)
    const eveAliceShared: Uint8Array = mixKeyExchange(eveKeyPair.private, aliceKeyPair.public)

    assert.notDeepStrictEqual(eveBobShared, bobShared)
    assert.notDeepStrictEqual(eveBobShared, aliceShared)
    assert.notDeepStrictEqual(eveAliceShared, bobShared)
    assert.notDeepStrictEqual(eveAliceShared, aliceShared)
  })
})

describe('KeyPair serialization', () => {
  test('should return the same keypair', () => {
    const keypair = generateKeyPair()
    const privateKeyBytes: Uint8Array = keypair.private.bytes
    const publicKeyBytes: Uint8Array = keypair.public.bytes

    const privateKey: PrivateKey = PrivateKey.fromBytes(privateKeyBytes)
    const publicKey: PublicKey = PublicKey.fromBytes(publicKeyBytes)

    assert.deepStrictEqual(privateKey.bytes, privateKeyBytes)
    assert.deepStrictEqual(publicKey.bytes, publicKeyBytes)
  })

  test('should not allow to parse a public key as a private key and vis-versa', () => {
    const keypair = generateKeyPair()
    const privateKeyBytes: Uint8Array = keypair.private.bytes
    const publicKeyBytes: Uint8Array = keypair.public.bytes

    const symmetricKey: Uint8Array = generateKey()

    assert.throws(() => PrivateKey.fromBytes(publicKeyBytes))
    assert.throws(() => PublicKey.fromBytes(privateKeyBytes))
    assert.throws(() => PrivateKey.fromBytes(symmetricKey))
    assert.throws(() => PublicKey.fromBytes(symmetricKey))
  })
})
