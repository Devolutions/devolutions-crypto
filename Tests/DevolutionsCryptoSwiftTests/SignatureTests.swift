import DevolutionsCryptoSwift
import XCTest

class SignatureTests: XCTestCase {
  func testSignature() throws {
    let data = Data("this is a test".utf8)
    let keypair = generateSigningKeypair()

    let signature = try sign(data: data, keypair: keypair.getPrivateKey())

    XCTAssertTrue(
      try verifySignature(data: data, publicKey: keypair.getPublicKey(), signature: signature))
  }

  func testWrongSignature() throws {
    let data = Data("this is test data".utf8)
    let wrongData = Data("this is wrong data".utf8)
    let keypair = generateSigningKeypair()

    let signature = try sign(data: data, keypair: keypair.getPrivateKey())

    XCTAssertFalse(
      try verifySignature(data: wrongData, publicKey: keypair.getPublicKey(), signature: signature))
  }
}
