import DevolutionsCryptoSwift
import XCTest

class HashingTests: XCTestCase {
  func testPasswordHash() throws {
    let password = Data("password".utf8)
    let hash = try hashPassword(password: password)

    XCTAssertTrue(try verifyPassword(password: password, hash: hash))
  }

  func testWrongPassword() throws {
    let password = Data("password".utf8)
    let hash = try hashPassword(password: password)

    XCTAssertFalse(try verifyPassword(password: Data("pa$$word".utf8), hash: hash))
    XCTAssertFalse(try verifyPassword(password: Data("Password".utf8), hash: hash))
    XCTAssertFalse(try verifyPassword(password: Data("password1".utf8), hash: hash))
  }

  func testPasswordHashV1() throws {
    let password = Data("password".utf8)
    let hash = try hashPassword(password: password, version: PasswordHashVersion.v1)

    XCTAssertTrue(try verifyPassword(password: password, hash: hash))
    XCTAssertFalse(try verifyPassword(password: Data("wrongpassword".utf8), hash: hash))
  }

  func testPasswordHashV2() throws {
    let password = Data("password".utf8)
    let hash = try hashPassword(password: password, version: PasswordHashVersion.v2)

    XCTAssertTrue(try verifyPassword(password: password, hash: hash))
    XCTAssertFalse(try verifyPassword(password: Data("wrongpassword".utf8), hash: hash))
  }
}
