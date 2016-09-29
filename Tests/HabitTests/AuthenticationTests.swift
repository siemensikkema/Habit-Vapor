@testable import Habit
import Auth
import Cache
import Essentials
import Fluent
import Foundation
import HTTP
import Nimble
import Quick
import Turnstile
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

extension Request {

    convenience init(body: [String: String]) throws {
        try self.init(body: JSON(Node(dictionary: body)))
    }

    convenience init(body: BodyRepresentable) throws {
        try self.init(
            method: .post,
            uri: "http://www.example.com",
            headers: ["Content-Type": "application/json; charset=utf-8"],
            body: body.makeBody())

        let cache = MemoryCache()
        let realm = AuthenticatorRealm(User.self)
        let sessionManager = CacheSessionManager(cache: cache, realm: realm)
        let turnstile = Turnstile(sessionManager: sessionManager, realm: realm)
        let subject = Subject(turnstile: turnstile)
        storage["subject"] = subject
    }
}

extension Node {

    init(dictionary: [String: String]) {
        var converted: [String: Node] = [:]

        dictionary.forEach {
            converted[$0.key] = .string($0.value)
        }

        self = .object(converted)
    }
}

final class AuthenticationSpec: QuickSpec {

    override func spec() {
        let date = Date(timeIntervalSince1970: 1475182344)
        let hasher = TestHasher()
        let jwtKey = "secret".data(using: .utf8)!
        let name = "Elon Musk"
        let password = "m@rs"
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NzUxODI5NDQsImlhdCI6MTQ3NTE4MjM0NCwiaWQiOiIxIiwibGFzdF9wYXNzd29yZF91cGRhdGUiOjE0NzUxODIzNDR9.qWOFt61XcNuzaO_C_sFd_pSD0FVnj8kA5mEKWiTrwkM"

        var authController: AuthController!
        var authError: Error?
        var userWasSaved: Bool!
        var response: ResponseRepresentable?

        beforeEach {
            authController = AuthController(
                jwtKey: jwtKey,
                hash: hasher,
                issueDate: date,
                createUser: { (username, salt, secret) in
                    User(name: username, salt: salt, secret: secret)
                },
                saveUser: { (user) in
                    userWasSaved = true
            })
            authError = nil
            response = nil
            userWasSaved = false

            Database.default = Database(MemoryDriver())
        }

        func createUser() {
            var user = User(name: name, salt: "", secret: password.bytes.hexString, lastPasswordUpdate: date)
            try! user.save()
        }

        describe("login") {

            func logIn(username: String, password: String) {
                do {
                    let request = try Request(body: ["username": username, "password": password])
                    response = try authController.logIn(request)
                } catch {
                    authError = error
                }
            }

            context("user not found") {

                beforeEach {
                    logIn(username: name, password: password)
                }

                it("throws an error") {
                    expect(authError as? Abort) == Abort.custom(status: .badRequest, message: "User not found or incorrect password")
                }
            }

            context("incorrect password") {

                beforeEach {
                    createUser()
                    logIn(username: name, password: "")
                }

                it("throws an error") {
                    expect(authError as? Abort) == Abort.custom(status: .badRequest, message: "User not found or incorrect password")
                }
            }

            context("correct password") {
                
                beforeEach {
                    createUser()
                    logIn(username: name, password: password)
                }

                it("succeeds") {
                    expect(authError).to(beNil())
                }

                it("returns a token") {
                    expect(response as? String) == token
                }
            }
        }

        describe("update password") {

            func updatePassword(username: String, password: String, newPassword: String) {
                do {
                    let request = try Request(body: ["username": username, "password": password, "new_password": newPassword])
                    response = try authController.updatePassword(request)
                } catch {
                    authError = error
                }
            }

            context("same password") {

                beforeEach {
                    updatePassword(username: name, password: password, newPassword: password)
                }

                it("throws an error") {
                    expect(authError as? Abort) == Abort.custom(status: .badRequest, message: "New password must be different")
                }

                it("does not save user") {
                    expect(userWasSaved) == false
                }
            }

            context("different password") {

                beforeEach {
                    createUser()
                    updatePassword(username: name, password: password, newPassword: "\(password)2")
                }

                it("succeeds") {
                    expect(authError).to(beNil())
                }

                it("saves user") {
                    expect(userWasSaved) == true
                }

                it("returns a different token") {
                    let newToken = response as? String
                    expect(newToken).toNot(beNil())
                    expect(newToken) != token
                }
            }
        }
    }
}
