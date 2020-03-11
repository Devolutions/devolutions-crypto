// These tests are there to make sure that the implementations are compatible between one language and another
import { deriveKey, base64encode, base64decode, decrypt } from 'devolutions-crypto'
import { expect } from 'chai'
import { describe, it } from 'mocha'

const encoder: TextEncoder = new TextEncoder()
const decoder: TextDecoder = new TextDecoder()

describe('Conformity Tests', () => {
  it('Key Derivation', () => {
    const derivedKey: Uint8Array = deriveKey(encoder.encode('testpassword'))
    const derivedKeyWithIterations: Uint8Array = deriveKey(encoder.encode('testPa$$'), null, 100)
    const derivedKeyWithSalt: Uint8Array = deriveKey(encoder.encode('testPa$$'), base64decode('tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA='), 100)

    expect(base64encode(derivedKey)).to.eql('ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=')
    expect(base64encode(derivedKeyWithIterations)).to.eql('ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=')
    expect(base64encode(derivedKeyWithSalt)).to.eql('ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=')
  })

  it('Symmetric Decrypt V1', () => {
    const key: Uint8Array = base64decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
    const ciphertext: Uint8Array = base64decode('DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A==')

    const decrypted: Uint8Array = decrypt(ciphertext, key)

    expect(decoder.decode(decrypted)).to.eql('test Ciph3rtext~')
  })

  it('Symmetric Decrypt V2', () => {
    const key: Uint8Array = base64decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
    const ciphertext: Uint8Array = base64decode('DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=')

    const decrypted: Uint8Array = decrypt(ciphertext, key)

    expect(decoder.decode(decrypted)).to.eql('test Ciph3rtext~2')
  })
})
