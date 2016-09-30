@testable import Habit
import Auth
import Cache
import Essentials
import Fluent
import Foundation
import HTTP
import JWT
import Nimble
import Punctual
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
        let name = "ElonMusk"
        let password = "m@rsm@rs"

        var authController: AuthController!
        var authError: Error?
        var id: String?
        var lastPasswordUpdate: Date?
        var expiration: Date?
        var issuedAt: Date?
        var userWasSaved: Bool!

        beforeEach {
            authController = AuthController(
                jwtKey: jwtKey,
                hash: hasher,
                issueDate: date,
                createUser: { (username, salt, secret) in
                    User(name: username, salt: salt, secret: secret, lastPasswordUpdate: date)
                },
                saveUser: { (user) in
                    user.id = .number(1)
                    userWasSaved = true
            })

            authError = nil
            expiration = nil
            id = nil
            issuedAt = nil
            lastPasswordUpdate = nil
            userWasSaved = false

            Database.default = Database(MemoryDriver())
        }

        func createUser() {
            do {
                var user = User(name: try Name(value: name).validated(), salt: "", secret: password.bytes.hexString, lastPasswordUpdate: date)
                try user.save()
            } catch {
                print(error)
            }
        }

        func parseResponse(_ response: ResponseRepresentable) {
            guard let token = response as? String else {
                return
            }
            do {
                let payload = try decode(token, algorithm: .hs256(jwtKey), verify: false)
                expiration = payload.expiration
                id = payload["id"]
                issuedAt = payload.issuedAt
                lastPasswordUpdate = payload["last_password_update"]
            } catch {
                print(error)
            }
        }

        describe("login") {

            func logIn(username: String, password: String) {
                do {
                    let request = try Request(body: ["username": username, "password": password])
                    parseResponse(try authController.logIn(request))
                } catch {
                    authError = error
                }
            }

            context("user not found") {

                beforeEach {
                    logIn(username: name, password: password)
                }

                it("fails") {
                    expect(authError as? Abort) == .custom(status: .badRequest, message: "User not found or incorrect password")
                }
            }

            context("incorrect password") {

                beforeEach {
                    createUser()
                    logIn(username: name, password: "")
                }

                it("fails") {
                    expect(authError as? Abort) == .custom(status: .badRequest, message: "User not found or incorrect password")
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

                describe("token") {

                    it("contains an id") {
                        expect(id) == "1"
                    }

                    it("contains an issuedAt date") {
                        expect(issuedAt) == date
                    }

                    it("contains an expiration date 10 minutes in the future") {
                        expect(expiration) == 10.minutes.from(date)
                    }

                    it("contains a lastPasswordUpdate date") {
                        expect(lastPasswordUpdate) == date
                    }
                }
            }
        }

        describe("register") {

            func register(username: String, password: String) {
                do {
                    let request = try Request(body: ["username": username, "password": password])
                    parseResponse(try authController.register(request))
                } catch {
                    authError = error
                }
            }

            context("new and valid user") {

                beforeEach {
                    register(username: name, password: password)
                }

                it("succeeds") {
                    expect(authError).to(beNil())
                }

                it("saves user") {
                    expect(userWasSaved) == true
                }

                describe("token") {

                    it("contains an id") {
                        expect(id) == "1"
                    }

                    it("contains an issuedAt date") {
                        expect(issuedAt) == date
                    }

                    it("contains an expiration date 10 minutes in the future") {
                        expect(expiration) == 10.minutes.from(date)
                    }

                    it("contains a lastPasswordUpdate date") {
                        expect(lastPasswordUpdate) == date
                    }
                }
            }

            context("existing user") {

                beforeEach {
                    createUser()
                    register(username: name, password: password)
                }

                it("fails") {
                    expect(authError as? Abort) == .custom(status: .badRequest, message: "User exists")
                }

                it("does not save user") {
                    expect(userWasSaved) == false
                }
            }

            context("invalid username") {

                beforeEach {
                    register(username: "", password: password)
                }

                it("fails") {
                    expect(authError as? ValidationErrorProtocol).toNot(beNil())
                }
            }

            context("invalid password") {

                beforeEach {
                    register(username: name, password: "")
                }

                it("fails") {
                    expect(authError as? ValidationErrorProtocol).toNot(beNil())
                }
            }
        }

        describe("update password") {

            func updatePassword(username: String, password: String, newPassword: String) {
                do {
                    let request = try Request(body: ["username": username, "password": password, "new_password": newPassword])
                    parseResponse(try authController.updatePassword(request))
                } catch {
                    authError = error
                }
            }

            context("same password") {

                beforeEach {
                    updatePassword(username: name, password: password, newPassword: password)
                }

                it("fails") {
                    expect(authError as? Abort) == .custom(status: .badRequest, message: "New password must be different")
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

                describe("token") {

                    it("contains an id") {
                        expect(id) == "1"
                    }

                    it("contains an issuedAt date") {
                        expect(issuedAt) == date
                    }

                    it("contains an expiration date 10 minutes in the future") {
                        expect(expiration) == 10.minutes.from(date)
                    }

                    it("contains a newer lastPasswordUpdate date") {
                        expect(lastPasswordUpdate) > date
                    }
                }

                context("invalid new password") {

                    beforeEach {
                        updatePassword(username: name, password: password, newPassword: "")
                    }

                    it("fails") {
                        expect(authError as? ValidationErrorProtocol).toNot(beNil())
                    }
                }
            }
        }
    }
}
