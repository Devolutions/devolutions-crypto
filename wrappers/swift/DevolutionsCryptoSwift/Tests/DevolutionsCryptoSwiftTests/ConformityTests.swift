import DevolutionsCryptoSwift
import XCTest

class ConformityTests: XCTestCase {

  func testDeriveKeyPbkdf2() throws {
    let derivedKey = deriveKeyPbkdf2(key: Data("testpassword".utf8), salt: nil)
    let derivedKeyWithIterations = deriveKeyPbkdf2(
      key: Data("testPa$$".utf8), salt: nil, iterations: 100)
    let derivedKeyWithSalt = deriveKeyPbkdf2(
      key: Data("testPa$$".utf8),
      salt: try base64Decode(data: "tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA="),
      iterations: 100
    )

    let expected = try base64Decode(data: "ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=")
    let expectedWithIterations = try base64Decode(
      data: "ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=")
    let expectedWithSalt = try base64Decode(data: "ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=")

    XCTAssertEqual(derivedKey, expected)
    XCTAssertEqual(derivedKeyWithIterations, expectedWithIterations)
    XCTAssertEqual(derivedKeyWithSalt, expectedWithSalt)
  }

  func testDeriveKeyArgon2() throws {
    let password = Data("password".utf8)
    let parameters = try Argon2Parameters.newFromBytes(
      data: try base64Decode(
        data: "AQAAACAAAAABAAAAIAAAAAEAAAACEwAAAAAQAAAAimFBkm3f8+f+YfLRnF5OoQ==")
    )
    let result = try deriveKeyArgon2(key: password, parameters: parameters)

    let expected = try base64Decode(data: "AcEN6Cb1Om6tomZScAM725qiXMzaxaHlj3iMiT/Ukq0=")

    XCTAssertEqual(result, expected)
  }

  func testSymmetricDecryptV1() throws {
    let key = try base64Decode(data: "ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=")
    let ciphertext = try base64Decode(
      data:
        "DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A=="
    )
    let result = try decrypt(data: ciphertext, key: key)
    let expected = Data("test Ciph3rtext~".utf8)

    XCTAssertEqual(result, expected)
  }

  func testSymmetricDecryptWithAadV1() throws {
    let key = try base64Decode(data: "ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=")
    let ciphertext = try base64Decode(
      data:
        "DQwCAAEAAQCeKfbTqYjfVCEPEiAJjiypBstPmZz0AnpliZKoR+WXTKdj2f/4ops0++dDBVZ+XdyE1KfqxViWVc9djy/HSCcPR4nDehtNI69heGCIFudXfQ=="
    )
    let aad = Data("this is some public data".utf8)
    let result = try decryptWithAad(data: ciphertext, key: key, aad: aad)
    let expected = Data("test Ciph3rtext~".utf8)

    XCTAssertEqual(result, expected)
  }

  func testSymmetricDecryptV2() throws {
    let key = try base64Decode(data: "ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=")
    let ciphertext = try base64Decode(
      data:
        "DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=")
    let result = try decrypt(data: ciphertext, key: key)
    let expected = Data("test Ciph3rtext~2".utf8)

    XCTAssertEqual(result, expected)
  }

  func testSymmetricDecryptWithAadV2() throws {
    let key = try base64Decode(data: "ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=")
    let ciphertext = try base64Decode(
      data:
        "DQwCAAEAAgA9bh989dao0Pvaz1NpJTI5m7M4br2qVjZtFwXXoXZOlkCjtqU/uif4pbNCcpEodzeP4YG1QvfKVQ==")
    let aad = Data("this is some public data".utf8)
    let result = try decryptWithAad(data: ciphertext, key: key, aad: aad)
    let expected = Data("test Ciph3rtext~".utf8)

    XCTAssertEqual(result, expected)
  }

  func testAsymmetricDecryptWithAadV2() throws {
    let privateKey = try base64Decode(
      data: "DQwBAAEAAQC9qf9UY1ovL/48ALGHL9SLVpVozbdjYsw0EPerUl3zYA==")
    let ciphertext = try base64Decode(
      data:
        "DQwCAAIAAgB1u62xYeyppWf83QdWwbwGUt5QuiAFZr+hIiFEvMRbXiNCE3RMBNbmgQkLr/vME0BeQa+uUTXZARvJcyNXHyAE4tSdw6o/psU/kw/Z/FbsPw=="
    )
    let aad = Data("this is some public data".utf8)
    let result = try decryptAsymmetricWithAad(data: ciphertext, key: privateKey, aad: aad)
    let expected = Data("testdata".utf8)

    XCTAssertEqual(result, expected)
  }

  func testPasswordHashingV1() throws {
    let hash1 = try base64Decode(
      data:
        "DQwDAAAAAQAQJwAAXCzLFoyeZhFSDYBAPiIWhCk04aoP/lalOoCl7D+skIY/i+3WT7dn6L8WvnfEq6flCd7i+IcKb3GEK4rCpzhDlw=="
    )
    let hash2 = try base64Decode(
      data:
        "DQwDAAAAAQAKAAAAmH1BBckBJYDD0xfiwkAk1xwKgw8a57YQT0Igm+Faa9LFamTeEJgqn/qHc2R/8XEyK2iLPkVy+IErdGLLtLKJ2g=="
    )

    XCTAssertTrue(try verifyPassword(password: Data("password1".utf8), hash: hash1))
    XCTAssertTrue(try verifyPassword(password: Data("password1".utf8), hash: hash2))
  }

  func testSignatureV1() throws {
    let publicKey = try base64Decode(
      data: "DQwFAAIAAQDeEvwlEigK5AXoTorhmlKP6+mbiUU2rYrVQ25JQ5xang==")
    let signature = try base64Decode(
      data:
        "DQwGAAAAAQD82uRk4sFC8vEni6pDNw/vOdN1IEDg9cAVfprWJZ/JBls9Gi61cUt5u6uBJtseNGZFT7qKLvp4NUZrAOL8FH0K"
    )

    XCTAssertTrue(
      try verifySignature(
        data: Data("this is a test".utf8), publicKey: publicKey, signature: signature))
    XCTAssertFalse(
      try verifySignature(
        data: Data("this is wrong".utf8), publicKey: publicKey, signature: signature))
  }
}
