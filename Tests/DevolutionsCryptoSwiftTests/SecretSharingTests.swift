import DevolutionsCryptoSwift
import XCTest

class SecretSharingTests: XCTestCase {
  func testSharedSecretDefault() throws {
    let shares = try generateSharedKey(nShares: 5, threshold: 3)

    let shareGroup1 = Array(shares[0...2])
    let shareGroup2 = Array(shares[1...3])
    let shareGroup3 = Array(shares[2...4])

    let key1 = try joinShares(shares: shareGroup1)
    let key2 = try joinShares(shares: shareGroup2)
    let key3 = try joinShares(shares: shareGroup3)

    XCTAssertEqual(key1.count, 32)
    XCTAssertNotEqual(key1, Data(repeating: UInt8(0), count: 32))
    XCTAssertEqual(key1, key2)
    XCTAssertEqual(key1, key3)
  }

  func testSharedSecretLarger() throws {
    let shares = try generateSharedKey(nShares: 5, threshold: 3, length: 41)

    let shareGroup1 = Array(shares[0...2])
    let shareGroup2 = Array(shares[1...3])
    let shareGroup3 = Array(shares[2...4])

    let key1 = try joinShares(shares: shareGroup1)
    let key2 = try joinShares(shares: shareGroup2)
    let key3 = try joinShares(shares: shareGroup3)

    XCTAssertEqual(key1.count, 41)
    XCTAssertNotEqual(key1, Data(repeating: UInt8(0), count: 41))
    XCTAssertEqual(key1, key2)
    XCTAssertEqual(key1, key3)
  }

  func testSharedSecretWrongParams() {
    XCTAssertThrowsError(try generateSharedKey(nShares: 3, threshold: 5)) { error in
      XCTAssertTrue(error is DevolutionsCryptoError)
    }
  }

  func testSharedSecretNotEnoughShares() {
    let shares = try! generateSharedKey(nShares: 5, threshold: 3)
    let sharesGroup = Array(shares[0...1])

    XCTAssertThrowsError(try joinShares(shares: sharesGroup)) { error in
      XCTAssertTrue(error is DevolutionsCryptoError)
    }
  }
}
