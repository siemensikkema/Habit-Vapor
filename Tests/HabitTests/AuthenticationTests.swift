@testable import Habit
import Foundation
import HTTP
import Nimble
import Quick
import URI
import Vapor

final class TestHasher: HashProtocol {
    var defaultKey: Bytes? {
        return nil
    }

    func make(_ string: Bytes, key: Bytes?) throws -> Bytes {
        return string
    }
}

final class AuthenticationSpec: QuickSpec {
    override func spec() {
        let jwtKey = "key".data(using: .utf8)!

        describe("update password") {

            let hasher = TestHasher()
            var authController: AuthController!
            var userWasSaved: Bool!

            beforeEach {
                userWasSaved = false
                authController = AuthController(
                    jwtKey: jwtKey,
                    hash: hasher,
                    createUser: { (username, salt, secret) in
                        User(name: username, salt: salt, secret: secret)
                    },
                    saveUser: { (user) in
                        userWasSaved = true
                })
            }

            context("same password") {

                let request: Request! = {
                    do {
                        let body = try JSON([
                            "username": "Elon Musk",
                            "password": "m@rs",
                            "new_password": "m@rs"])
                            .makeBytes()

                        let request = try Request(
                            method: .post,
                            uri: "http://www.example.com",
                            headers: ["Content-Type": "application/json; charset=utf-8"],
                            body: .data(body))
                        return request
                    } catch {
                        return nil
                    }
                }()
                var authError: Abort?

                beforeEach {
                    do {
                        _ = try authController.updatePassword(request)
                    } catch {
                        authError = error as? Abort
                    }
                }

                it("throws") {
                    expect(authError) == Abort.custom(status: .badRequest, message: "New password must be different")
                }

                it("does not save user") {
                    expect(userWasSaved) == false
                }
            }
        }
    }
}
