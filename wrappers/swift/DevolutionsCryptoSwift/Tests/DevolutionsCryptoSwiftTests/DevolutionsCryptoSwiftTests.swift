import XCTest
@testable import DevolutionsCryptoSwift

final class DevolutionsCryptoSwiftTests: XCTestCase {
    func testExample() throws {
        // XCTest Documentation
        // https://developer.apple.com/documentation/xctest

        // Defining Test Cases and Test Methods
        // https://developer.apple.com/documentation/xctest/defining_test_cases_and_test_methods
        let key = generateKey()

        assert(key.count == 32)
    }
}
