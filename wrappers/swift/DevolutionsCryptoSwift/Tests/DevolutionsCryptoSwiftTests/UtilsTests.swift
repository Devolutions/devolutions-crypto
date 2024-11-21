import DevolutionsCryptoSwift
import XCTest

class UtilsTests: XCTestCase {
  func testGenerateKeyDefault() {
    let key = generateKey()
    XCTAssertEqual(key.count, 32)
    XCTAssertNotEqual(key, Data(repeating: UInt8(0), count: 32))
  }

  func testGenerateKeyLonger() {
    let key = generateKey(length: 41)
    XCTAssertEqual(key.count, 41)
    XCTAssertNotEqual(key, Data(repeating: UInt8(0), count: 41))
  }

  func testGenerateKeyActuallyRandom() {
    let key1 = generateKey()
    let key2 = generateKey()
    XCTAssertNotEqual(key1, key2)
  }

  func testDeriveKeyPbkdfDefault() {
    let password = Data("password".utf8)
    let result = deriveKeyPbkdf2(key: password, salt: nil, iterations: 10)
    XCTAssertEqual(result.count, 32)
    XCTAssertNotEqual(result, Data(repeating: UInt8(0), count: 32))
  }

  func testDeriveKeyPbkdfLarger() {
    let password = Data("password".utf8)
    let result = deriveKeyPbkdf2(key: password, salt: nil, iterations: 10, length: 41)
    XCTAssertEqual(result.count, 41)
    XCTAssertNotEqual(result, Data(repeating: UInt8(0), count: 41))
  }

  func testDeriveKeyPbkdfDeterministic() {
    let password = Data("password".utf8)
    let result1 = deriveKeyPbkdf2(key: password, salt: nil, iterations: 10)
    let result2 = deriveKeyPbkdf2(key: password, salt: nil, iterations: 10)

    XCTAssertEqual(result1.count, 32)
    XCTAssertNotEqual(result1, Data(repeating: UInt8(0), count: 32))
    XCTAssertEqual(result1, result2)
  }

  func testDeriveKeyPbkdfDifferent() {
    let password = Data("password".utf8)
    let salt = Data("thisisasalt".utf8)
    let iterations: UInt32 = 10

    let result = deriveKeyPbkdf2(key: password, salt: salt, iterations: iterations)
    let differentPass = deriveKeyPbkdf2(
      key: Data("pa$$word".utf8), salt: salt, iterations: iterations)
    let differentSalt = deriveKeyPbkdf2(
      key: password, salt: Data("this1sasalt".utf8), iterations: iterations)
    let differentIterations = deriveKeyPbkdf2(key: password, salt: salt, iterations: 11)

    XCTAssertNotEqual(result, differentPass)
    XCTAssertNotEqual(result, differentSalt)
    XCTAssertNotEqual(result, differentIterations)
  }

  func testDeriveKeyArgon2() throws {
    let parameters = Argon2ParametersBuilder().build()
    let password = Data("password".utf8)

    let result = try deriveKeyArgon2(key: password, parameters: parameters)
    XCTAssertEqual(result.count, 32)
    XCTAssertNotEqual(result, Data(repeating: UInt8(0), count: 32))
  }

  func testValidateHeaderValid() throws {
    let validCiphertext = try base64Decode(data: "DQwCAAAAAQA=")
    let validPasswordHash = try base64Decode(data: "DQwDAAAAAQA=")
    let validShare = try base64Decode(data: "DQwEAAAAAQA=")
    let validPrivateKey = try base64Decode(data: "DQwBAAEAAQA=")
    let validPublicKey = try base64Decode(data: "DQwBAAEAAQA=")

    XCTAssertTrue(validateHeader(data: validCiphertext, dataType: DataType.ciphertext))
    XCTAssertTrue(validateHeader(data: validPasswordHash, dataType: DataType.passwordHash))
    XCTAssertTrue(validateHeader(data: validShare, dataType: DataType.share))
    XCTAssertTrue(validateHeader(data: validPublicKey, dataType: DataType.key))
    XCTAssertTrue(validateHeader(data: validPrivateKey, dataType: DataType.key))
  }

  func testValidateHeaderInvalid() throws {
    let validCiphertext = try base64Decode(data: "DQwCAAAAAQA=")
    XCTAssertFalse(validateHeader(data: validCiphertext, dataType: DataType.passwordHash))

    let invalidSignature = try base64Decode(data: "DAwBAAEAAQA=")
    let invalidType = try base64Decode(data: "DQwIAAEAAQA=")
    let invalidSubtype = try base64Decode(data: "DQwBAAgAAQA=")
    let invalidVersion = try base64Decode(data: "DQwBAAEACAA=")

    XCTAssertFalse(validateHeader(data: invalidSignature, dataType: DataType.key))
    XCTAssertFalse(validateHeader(data: invalidType, dataType: DataType.key))
    XCTAssertFalse(validateHeader(data: invalidSubtype, dataType: DataType.key))
    XCTAssertFalse(validateHeader(data: invalidVersion, dataType: DataType.key))

    let notLongEnough = try base64Decode(data: "DQwBAAEAAQ==")
    XCTAssertFalse(validateHeader(data: notLongEnough, dataType: DataType.key))
  }

  func testBase64Encode() {
    let input: Data = Data([0x41, 0x42, 0x43, 0x44, 0x45])
    let expected = "QUJDREU="
    let result = base64Encode(data: input)
    XCTAssertEqual(result, expected)
  }

  func testBase64Decode() throws {
    let input = "QUJDREU="
    let expected: Data = Data([0x41, 0x42, 0x43, 0x44, 0x45])
    let result = try base64Decode(data: input)
    XCTAssertEqual(result, expected)
  }

  func testBase64UrlEncode() {
    let input1 = Data("Ab6/".utf8)
    let expected1 = "QWI2Lw"
    let result1 = base64EncodeUrl(data: input1)
    XCTAssertEqual(result1, expected1)

    let input2 = Data("Ab6/75".utf8)
    let expected2 = "QWI2Lzc1"
    let result2 = base64EncodeUrl(data: input2)
    XCTAssertEqual(result2, expected2)

    let input3 = Data([0xff, 0xff, 0xfe, 0xff])
    let expected3 = "___-_w"
    let result3 = base64EncodeUrl(data: input3)
    XCTAssertEqual(result3, expected3)
  }

  func testBase64UrlDecode() throws {
    let input1 = "QWI2Lw"
    let expected1 = Data("Ab6/".utf8)
    let result1 = try base64DecodeUrl(data: input1)
    XCTAssertEqual(result1, expected1)

    let input2 = "QWI2Lzc1"
    let expected2 = Data("Ab6/75".utf8)
    let result2 = try base64DecodeUrl(data: input2)
    XCTAssertEqual(result2, expected2)

    let input3 = "___-_w"
    let expected3 = Data([0xff, 0xff, 0xfe, 0xff])
    let result3 = try base64DecodeUrl(data: input3)
    XCTAssertEqual(result3, expected3)
  }
}
