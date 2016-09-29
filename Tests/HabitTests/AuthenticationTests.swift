@testable import Habit
import HTTP
import URI
import Vapor
import XCTest

final class TestHasher: HashProtocol {
    var defaultKey: Bytes? {
        return nil
    }

    func make(_ string: Bytes, key: Bytes?) throws -> Bytes {
        return string
    }
}

final class AuthenticationTests: XCTestCase {
    let jwtKey = "key".data(using: .utf8)!

    func testChangePasswordRequiresDifferentPassword() throws {
        let hash = TestHasher()

        var userWasSaved = false

        let authController = AuthController(
            jwtKey: jwtKey,
            hash: hash,
            createUser: { (username, salt, secret) in
                User(name: username, salt: salt, secret: secret)
            },
            saveUser: { (user) in
                userWasSaved = true
            })

        let body = try JSON(["username": "Elon Musk", "password": "m@rs", "new_password": "m@rs"])
            .makeBytes()

        let request = try Request(
            method: .post,
            uri: "http://www.example.com",
            headers: ["Content-Type": "application/json; charset=utf-8"],
            body: .data(body))

        XCTAssertThrowsError(try authController.changePassword(request)) { error in
            guard let abort = error as? Abort,
                case .custom(let status, let message) = abort,
                status == .badRequest, message == "New password must be different" else {
                    XCTFail("Unexpected error: \(error)")
                    return
            }
        }
        XCTAssertFalse(userWasSaved)
    }
}
