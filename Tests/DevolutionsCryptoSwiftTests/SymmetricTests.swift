import DevolutionsCryptoSwift
import XCTest

class SymmetricTests: XCTestCase {
  func testEncryptDecrypt() throws {
    let data = Data("This is some test data".utf8)
    let key = try generateKey()

    let encrypted = try encrypt(data: data, key: key)
    let decrypted = try decrypt(data: encrypted, key: key)

    XCTAssertFalse(data.elementsEqual(encrypted))
    XCTAssertEqual(data, decrypted)
  }

  func testEncryptDecryptWithAad() throws {
    let data = Data("This is some test data".utf8)
    let aad = Data("This is some public data".utf8)

    let key = try generateKey()

    let encrypted = try encryptWithAad(data: data, key: key, aad: aad)
    let decrypted = try decryptWithAad(data: encrypted, key: key, aad: aad)

    XCTAssertFalse(data.elementsEqual(encrypted))
    XCTAssertEqual(data, decrypted)
  }

  func testEncryptDecryptWithWrongAad() throws {
    let data = Data("This is some test data".utf8)
    let aad = Data("This is some public data".utf8)
    let wrongAad = Data("this is some public data".utf8)

    let key = try generateKey()

    let encrypted = try encryptWithAad(data: data, key: key, aad: aad)

    XCTAssertThrowsError(try decryptWithAad(data: encrypted, key: key, aad: wrongAad)) { error in
      XCTAssertTrue(error is DevolutionsCryptoError)
    }
  }
}
