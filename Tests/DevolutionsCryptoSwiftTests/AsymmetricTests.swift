import DevolutionsCryptoSwift
import XCTest

class AsymmetricTests: XCTestCase {

  func testGenerateKeypair() {
    let keypair = generateKeypair()

    XCTAssertFalse(keypair.publicKey.isEmpty)
    XCTAssertFalse(keypair.privateKey.isEmpty)
    XCTAssertNotEqual(keypair.privateKey, keypair.publicKey)
  }

  func testEncryptDecryptAsymmetric() throws {
    let data = Data("This is some test data".utf8)
    let keypair = generateKeypair()

    let encrypted = try encryptAsymmetric(data: data, key: keypair.publicKey)
    let decrypted = try decryptAsymmetric(data: encrypted, key: keypair.privateKey)

    XCTAssertFalse(data.elementsEqual(encrypted))
    XCTAssertEqual(data, decrypted)
  }

  func testEncryptDecryptAsymmetricWithAad() throws {
    let data = Data("This is some test data".utf8)
    let aad = Data("This is some public data".utf8)
    let keypair = generateKeypair()

    let encrypted = try encryptAsymmetricWithAad(data: data, key: keypair.publicKey, aad: aad)
    let decrypted = try decryptAsymmetricWithAad(data: encrypted, key: keypair.privateKey, aad: aad)

    XCTAssertFalse(data.elementsEqual(encrypted))
    XCTAssertEqual(data, decrypted)
  }

  func testEncryptDecryptAsymmetricWithWrongAad() throws {
    let data = Data("This is some test data".utf8)
    let aad = Data("This is some public data".utf8)
    let wrongAad = Data("this is some public data".utf8)
    let keypair = generateKeypair()

    let encrypted = try encryptAsymmetricWithAad(data: data, key: keypair.publicKey, aad: aad)

    XCTAssertThrowsError(
      try decryptAsymmetricWithAad(data: encrypted, key: keypair.privateKey, aad: wrongAad)
    ) { error in
      XCTAssertTrue(error is DevolutionsCryptoError)
    }
  }

  func testMixKeyExchange() throws {
    let bobKeypair = generateKeypair()
    let aliceKeypair = generateKeypair()

    let bobShared = try mixKeyExchange(
      privateKey: bobKeypair.privateKey, publicKey: aliceKeypair.publicKey)
    let aliceShared = try mixKeyExchange(
      privateKey: aliceKeypair.privateKey, publicKey: bobKeypair.publicKey)

    XCTAssertEqual(bobShared.count, 32)
    XCTAssertNotEqual(bobShared, Data(repeating: UInt8(0), count: 32))
    XCTAssertEqual(bobShared, aliceShared)
  }

  func testMixKeyExchangeNotEquals() throws {
    let bobKeypair = generateKeypair()
    let aliceKeypair = generateKeypair()
    let eveKeypair = generateKeypair()

    let bobAliceShared = try mixKeyExchange(
      privateKey: bobKeypair.privateKey, publicKey: aliceKeypair.publicKey)
    let aliceBobShared = try mixKeyExchange(
      privateKey: aliceKeypair.privateKey, publicKey: bobKeypair.publicKey)

    let eveBobShared = try mixKeyExchange(
      privateKey: eveKeypair.privateKey, publicKey: bobKeypair.publicKey)
    let eveAliceShared = try mixKeyExchange(
      privateKey: eveKeypair.privateKey, publicKey: aliceKeypair.publicKey)

    XCTAssertNotEqual(eveBobShared, bobAliceShared)
    XCTAssertNotEqual(eveBobShared, aliceBobShared)
    XCTAssertNotEqual(eveAliceShared, bobAliceShared)
    XCTAssertNotEqual(eveAliceShared, aliceBobShared)
  }
}
