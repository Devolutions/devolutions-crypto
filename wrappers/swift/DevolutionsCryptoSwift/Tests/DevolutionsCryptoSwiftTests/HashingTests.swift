import DevolutionsCryptoSwift
import XCTest

class HashingTests: XCTestCase {
  func testPasswordHash() throws {
    let password = Data("password".utf8)
    let hash = try hashPassword(password: password, iterations: 10)

    XCTAssertTrue(try verifyPassword(password: password, hash: hash))
  }

  func testWrongPassword() throws {
    let password = Data("password".utf8)
    let hash = try hashPassword(password: password, iterations: 10)

    XCTAssertFalse(try verifyPassword(password: Data("pa$$word".utf8), hash: hash))
    XCTAssertFalse(try verifyPassword(password: Data("Password".utf8), hash: hash))
    XCTAssertFalse(try verifyPassword(password: Data("password1".utf8), hash: hash))
  }
}
