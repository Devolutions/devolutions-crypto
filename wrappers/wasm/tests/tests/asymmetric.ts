import {
  KeyPair, PublicKey, PrivateKey, Argon2Parameters,
  deriveKeyPair, generateKey, generateKeyPair, encryptAsymmetric, decryptAsymmetric, mixKeyExchange
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

describe('deriveKeyPair', () => {
  it('should generate the same keypair', () => {
    const password: Uint8Array = encoder.encode('password')
    let parameters: Argon2Parameters = new Argon2Parameters()
    parameters.memory = 32

    const derivedKeyPair1: KeyPair = deriveKeyPair(password, parameters)

    const parametersBytes: Uint8Array = parameters.bytes
    parameters = Argon2Parameters.fromBytes(parametersBytes)

    const derivedKeyPair2: KeyPair = deriveKeyPair(password, parameters)

    expect(derivedKeyPair1.private.bytes).to.eql(derivedKeyPair2.private.bytes)
    expect(derivedKeyPair1.public.bytes).to.eql(derivedKeyPair2.public.bytes)
  })

  it('should not generate the same keypairs with different salts', () => {
    const password: Uint8Array = encoder.encode('password')
    let parameters: Argon2Parameters = new Argon2Parameters()
    parameters.memory = 32

    const derivedKeyPair1: KeyPair = deriveKeyPair(password, parameters)

    parameters = new Argon2Parameters()
    parameters.memory = 32
    const derivedKeyPair2: KeyPair = deriveKeyPair(password, parameters)

    expect(derivedKeyPair1.private.bytes).to.not.eql(derivedKeyPair2.private.bytes)
    expect(derivedKeyPair1.public.bytes).to.not.eql(derivedKeyPair2.public.bytes)
  })

  it('should not generate the same keypair with different passwords', () => {
    let password: Uint8Array = encoder.encode('password')
    const parameters: Argon2Parameters = new Argon2Parameters()
    parameters.memory = 32
    const derivedKeyPair1: KeyPair = deriveKeyPair(password, parameters)

    password = encoder.encode('password1')
    const derivedKeyPair2: KeyPair = deriveKeyPair(password, parameters)

    expect(derivedKeyPair1.private.bytes).to.not.eql(derivedKeyPair2.private.bytes)
    expect(derivedKeyPair1.public.bytes).to.not.eql(derivedKeyPair2.public.bytes)
  })

  it('should not generate the same keypair with different parameters', () => {
    const password: Uint8Array = encoder.encode('password')
    const parameters: Argon2Parameters = new Argon2Parameters()
    parameters.iterations = 2
    parameters.memory = 32
    parameters.lanes = 1
    const derivedKeyPair: KeyPair = deriveKeyPair(password, parameters)

    parameters.iterations = 1
    const derivedKeyPairWithDifferentIterations: KeyPair = deriveKeyPair(password, parameters)
    parameters.iterations = 2

    parameters.memory = 33
    const derivedKeyPairWithDifferentMemory: KeyPair = deriveKeyPair(password, parameters)
    parameters.memory = 32

    parameters.lanes = 2
    const derivedKeyPairWithDifferentLanes: KeyPair = deriveKeyPair(password, parameters)

    expect(derivedKeyPair.private.bytes).to.not.eql(derivedKeyPairWithDifferentIterations.private.bytes)
    expect(derivedKeyPair.public.bytes).to.not.eql(derivedKeyPairWithDifferentIterations.public.bytes)

    expect(derivedKeyPair.private.bytes).to.not.eql(derivedKeyPairWithDifferentMemory.private.bytes)
    expect(derivedKeyPair.public.bytes).to.not.eql(derivedKeyPairWithDifferentMemory.public.bytes)

    expect(derivedKeyPair.private.bytes).to.not.eql(derivedKeyPairWithDifferentLanes.private.bytes)
    expect(derivedKeyPair.public.bytes).to.not.eql(derivedKeyPairWithDifferentLanes.public.bytes)
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
