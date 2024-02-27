import {
  KeyPair, PublicKey, PrivateKey, Argon2Parameters,
  generateKey, generateKeyPair, encryptAsymmetric, decryptAsymmetric, mixKeyExchange
} from 'devolutions-crypto'
import { expect } from 'chai'
import { describe, it } from 'mocha'

const encoder: TextEncoder = new TextEncoder()

describe('generateKeyPair', () => {
  it('should generate a random keypair', () => {
    const keypair: KeyPair = generateKeyPair()
    expect(keypair.private.bytes).to.not.have.lengthOf(0)
    expect(keypair.public.bytes).to.not.have.lengthOf(0)
    expect(keypair.private).to.not.eql(keypair.public)
  })
})

describe('asymmetricEncrypt/asymmetricDecrypt', () => {
  it('should be able to encrypt and decrypt', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const keypair: KeyPair = generateKeyPair()
    const encrypted: Uint8Array = encryptAsymmetric(input, keypair.public)
    const decrypted: Uint8Array = decryptAsymmetric(encrypted, keypair.private)
    expect(encrypted).to.not.contains(input)
    expect(decrypted).to.eql(input)
  })

  it('should be able to encrypt and decrypt with an AAD', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const aad: Uint8Array = encoder.encode('This is some public data')
    const keypair: KeyPair = generateKeyPair()
    const encrypted: Uint8Array = encryptAsymmetric(input, keypair.public, aad)
    const decrypted: Uint8Array = decryptAsymmetric(encrypted, keypair.private, aad)
    expect(encrypted).to.not.contains(input)
    expect(decrypted).to.eql(input)
  })

  it('should fail if AAD is invalid', () => {
    const input: Uint8Array = encoder.encode('This is some test data')
    const aad: Uint8Array = encoder.encode('This is some public data')
    const wrongAad: Uint8Array = encoder.encode('this is some public data')
    const keypair: KeyPair = generateKeyPair()
    const encrypted: Uint8Array = encryptAsymmetric(input, keypair.public, aad)

    expect(() => decryptAsymmetric(encrypted, keypair.private)).to.throw()
    expect(() => decryptAsymmetric(encrypted, keypair.private, wrongAad)).to.throw()
  })
})

describe('mixKeyExchange', () => {
  it('should give the same 32 byte shared key', () => {
    const bobKeyPair: KeyPair = generateKeyPair()
    const aliceKeyPair: KeyPair = generateKeyPair()

    const bobShared: Uint8Array = mixKeyExchange(bobKeyPair.private, aliceKeyPair.public)
    const aliceShared: Uint8Array = mixKeyExchange(aliceKeyPair.private, bobKeyPair.public)

    expect(bobShared).to.have.lengthOf(32)
    expect(bobShared).to.not.eql(new Array(32).fill(0))
    expect(bobShared).to.eql(aliceShared)
  })

  it('should not give the same 32 byte shared key', () => {
    const bobKeyPair: KeyPair = generateKeyPair()
    const aliceKeyPair: KeyPair = generateKeyPair()
    const eveKeyPair: KeyPair = generateKeyPair()

    const bobShared: Uint8Array = mixKeyExchange(bobKeyPair.private, aliceKeyPair.public)
    const aliceShared: Uint8Array = mixKeyExchange(aliceKeyPair.private, bobKeyPair.public)

    const eveBobShared: Uint8Array = mixKeyExchange(eveKeyPair.private, bobKeyPair.public)
    const eveAliceShared: Uint8Array = mixKeyExchange(eveKeyPair.private, aliceKeyPair.public)

    expect(eveBobShared).to.not.eql(bobShared)
    expect(eveBobShared).to.not.eql(aliceShared)
    expect(eveAliceShared).to.not.eql(bobShared)
    expect(eveAliceShared).to.not.eql(aliceShared)
  })
})

describe('KeyPair serialization', () => {
  it('should return the same keypair', () => {
    const keypair = generateKeyPair()
    const privateKeyBytes: Uint8Array = keypair.private.bytes
    const publicKeyBytes: Uint8Array = keypair.public.bytes

    const privateKey: PrivateKey = PrivateKey.fromBytes(privateKeyBytes)
    const publicKey: PublicKey = PublicKey.fromBytes(publicKeyBytes)

    expect(privateKey.bytes).to.eql(privateKeyBytes)
    expect(publicKey.bytes).to.eql(publicKeyBytes)
  })

  it('should not allow to parse a public key as a private key and vis-versa', () => {
    const keypair = generateKeyPair()
    const privateKeyBytes: Uint8Array = keypair.private.bytes
    const publicKeyBytes: Uint8Array = keypair.public.bytes

    const symmetricKey: Uint8Array = generateKey()

    expect(() => PrivateKey.fromBytes(publicKeyBytes)).to.throw()
    expect(() => PublicKey.fromBytes(privateKeyBytes)).to.throw()
    expect(() => PrivateKey.fromBytes(symmetricKey)).to.throw()
    expect(() => PublicKey.fromBytes(symmetricKey)).to.throw()
  })
})
