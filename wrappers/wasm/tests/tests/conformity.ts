// These tests are there to make sure that the implementations are compatible between one language and another
import {
  KeyPair, deriveKeyPbkdf2, base64encode, base64decode, decrypt, Argon2Parameters, PrivateKey, SigningPublicKey, decryptAsymmetric, verifyPassword, verifySignature, deriveKeyArgon2
} from 'devolutions-crypto'
import { expect } from 'chai'
import { describe, it } from 'mocha'

const encoder: TextEncoder = new TextEncoder()
const decoder: TextDecoder = new TextDecoder()

describe('Conformity Tests', () => {
  it('Key Derivation PBKDF2', () => {
    const derivedKey: Uint8Array = deriveKeyPbkdf2(encoder.encode('testpassword'))
    const derivedKeyWithIterations: Uint8Array = deriveKeyPbkdf2(encoder.encode('testPa$$'), null, 100)
    const derivedKeyWithSalt: Uint8Array = deriveKeyPbkdf2(encoder.encode('testPa$$'), base64decode('tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA='), 100)

    expect(base64encode(derivedKey)).to.eql('ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=')
    expect(base64encode(derivedKeyWithIterations)).to.eql('ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=')
    expect(base64encode(derivedKeyWithSalt)).to.eql('ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=')
  })

  it('Key Derivation Argon2', () => {
    const parameters: Argon2Parameters = Argon2Parameters.fromBytes(base64decode('AQAAACAAAAABAAAAIAAAAAEAAAACEwAAAAAQAAAAimFBkm3f8+f+YfLRnF5OoQ=='))
    const result: Uint8Array = deriveKeyArgon2(encoder.encode('password'), parameters)

    expect(base64encode(result)).to.eql('AcEN6Cb1Om6tomZScAM725qiXMzaxaHlj3iMiT/Ukq0=')
  })

  it('Symmetric Decrypt V1', () => {
    const key: Uint8Array = base64decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
    const ciphertext: Uint8Array = base64decode('DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A==')

    const decrypted: Uint8Array = decrypt(ciphertext, key)

    expect(decoder.decode(decrypted)).to.eql('test Ciph3rtext~')
  })

  it('Symmetric Decrypt with AAD V1', () => {
    const key: Uint8Array = base64decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
    const ciphertext: Uint8Array = base64decode('DQwCAAEAAQCeKfbTqYjfVCEPEiAJjiypBstPmZz0AnpliZKoR+WXTKdj2f/4ops0++dDBVZ+XdyE1KfqxViWVc9djy/HSCcPR4nDehtNI69heGCIFudXfQ==')
    const aad: Uint8Array = encoder.encode('this is some public data')

    const decrypted: Uint8Array = decrypt(ciphertext, key, aad)

    expect(decoder.decode(decrypted)).to.eql('test Ciph3rtext~')
  })

  it('Symmetric Decrypt V2', () => {
    const key: Uint8Array = base64decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
    const ciphertext: Uint8Array = base64decode('DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=')

    const decrypted: Uint8Array = decrypt(ciphertext, key)

    expect(decoder.decode(decrypted)).to.eql('test Ciph3rtext~2')
  })

  it('Symmetric Decrypt with AAD V2', () => {
    const key: Uint8Array = base64decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=')
    const ciphertext: Uint8Array = base64decode('DQwCAAEAAgA9bh989dao0Pvaz1NpJTI5m7M4br2qVjZtFwXXoXZOlkCjtqU/uif4pbNCcpEodzeP4YG1QvfKVQ==')
    const aad: Uint8Array = encoder.encode('this is some public data')

    const decrypted: Uint8Array = decrypt(ciphertext, key, aad)

    expect(decoder.decode(decrypted)).to.eql('test Ciph3rtext~')
  })

  it('Asymmetric Decrypt V2', () => {
    const privateKey: PrivateKey = PrivateKey.fromBytes(base64decode('DQwBAAEAAQAAwQ3oJvU6bq2iZlJwAzvbmqJczNrFoeWPeIyJP9SSbQ=='))
    const result: Uint8Array = decryptAsymmetric(base64decode('DQwCAAIAAgCIG9L2MTiumytn7H/p5I3aGVdhV3WUL4i8nIeMWIJ1YRbNQ6lEiQDAyfYhbs6gg1cD7+5Ft2Q5cm7ArsGfiFYWnscm1y7a8tAGfjFFTonzrg=='), privateKey)

    expect(decoder.decode(result)).to.eql('testdata')
  })

  it('Asymmetric Decrypt V2 with AAD', () => {
    const privateKey: PrivateKey = PrivateKey.fromBytes(base64decode('DQwBAAEAAQC9qf9UY1ovL/48ALGHL9SLVpVozbdjYsw0EPerUl3zYA=='))
    const aad: Uint8Array = encoder.encode('this is some public data')

    const result: Uint8Array = decryptAsymmetric(base64decode('DQwCAAIAAgB1u62xYeyppWf83QdWwbwGUt5QuiAFZr+hIiFEvMRbXiNCE3RMBNbmgQkLr/vME0BeQa+uUTXZARvJcyNXHyAE4tSdw6o/psU/kw/Z/FbsPw=='), privateKey, aad)

    expect(decoder.decode(result)).to.eql('testdata')
  })

  it('Password Hashing V1', () => {
    const hash1: Uint8Array = base64decode('DQwDAAAAAQAQJwAAXCzLFoyeZhFSDYBAPiIWhCk04aoP/lalOoCl7D+skIY/i+3WT7dn6L8WvnfEq6flCd7i+IcKb3GEK4rCpzhDlw==')
    const hash2: Uint8Array = base64decode('DQwDAAAAAQAKAAAAmH1BBckBJYDD0xfiwkAk1xwKgw8a57YQT0Igm+Faa9LFamTeEJgqn/qHc2R/8XEyK2iLPkVy+IErdGLLtLKJ2g==')
    expect(verifyPassword(encoder.encode('password1'), hash1)).to.eql(true)
    expect(verifyPassword(encoder.encode('password1'), hash2)).to.eql(true)
  })

  it('Signature V1', () => {
    const public_key_bytes: Uint8Array = base64decode('DQwFAAIAAQDeEvwlEigK5AXoTorhmlKP6+mbiUU2rYrVQ25JQ5xang==')
    const signature: Uint8Array = base64decode('DQwGAAAAAQD82uRk4sFC8vEni6pDNw/vOdN1IEDg9cAVfprWJZ/JBls9Gi61cUt5u6uBJtseNGZFT7qKLvp4NUZrAOL8FH0K')

    const public_key = SigningPublicKey.fromBytes(public_key_bytes);

    expect(verifySignature(encoder.encode('this is a test'), public_key, signature)).to.eql(true)
    expect(verifySignature(encoder.encode('this is wrong'), public_key, signature)).to.eql(false)
  })
})
