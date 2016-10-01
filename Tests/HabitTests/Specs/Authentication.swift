@testable import Habit
import Auth
import Essentials
import Fluent
import Foundation
import HTTP
import JWT
import Nimble
import Punctual
import Quick
import Vapor

final class TestHasher: HashProtocol {

    var defaultKey: Bytes? {
        return nil
    }

    func make(_ string: Bytes, key: Bytes?) throws -> Bytes {
        return string
    }
}

func error(from expression: () throws -> Void) -> Error? {
    do {
        try expression()
        return nil
    } catch {
        return error
    }
}

final class AuthenticationSpec: QuickSpec {

    override func spec() {

        // initializing date this way enables comparison
        let date = Date(timeIntervalSince1970: Date().timeIntervalSince1970)
        let hasher = TestHasher()
        let jwtKey = "secret".data(using: .utf8)!
        let name = "ElonMusk"
        let password = "g0t0m@rs"

        var authError: Error?
        var controller: AuthController!
        var expiration: Date?
        var id: String?
        var issuedAt: Date?
        var lastPasswordUpdate: Date?
        var token: String!
        var userWasSaved: Bool!

        func createUser() {
            do {
                var user = User(name: try Name(value: name).validated(), salt: "", secret: password.bytes.hexString, lastPasswordUpdate: date)
                try user.save()
            } catch {
                print(error)
            }
        }

        func logIn(username: String, password: String) {
            do {
                let request = try Request(body: ["username": username, "password": password])
                parseResponse(try controller.logIn(request))
            } catch {
                authError = error
            }
        }

        func register(username: String, password: String) {
            do {
                let request = try Request(body: ["username": username, "password": password])
                parseResponse(try controller.register(request))
            } catch {
                authError = error
            }
        }

        func updatePassword(username: String, password: String, newPassword: String) {
            do {
                let request = try Request(body: ["username": username, "password": password, "new_password": newPassword])
                parseResponse(try controller.updatePassword(request))
            } catch {
                authError = error
            }
        }

        func parseResponse(_ response: ResponseRepresentable) {
            guard let tokenResponse = response as? String else {
                return
            }
            do {
                token = tokenResponse
                let payload = try decode(tokenResponse, algorithm: .hs256(jwtKey), verify: false)
                expiration = payload.expiration
                id = payload["id"]
                issuedAt = payload.issuedAt
                lastPasswordUpdate = payload["last_password_update"]
            } catch {
                print(error)
            }
        }

        beforeEach {
            controller = AuthController(
                jwtKey: jwtKey,
                hash: hasher,
                issueDate: date,
                createUser: { (username, salt, secret) in
                    User(name: username, salt: salt, secret: secret, lastPasswordUpdate: date)
                },
                saveUser: { (user) in
                    try user.save()
                    userWasSaved = true
            })

            authError = nil
            expiration = nil
            id = nil
            issuedAt = nil
            lastPasswordUpdate = nil
            token = nil
            userWasSaved = false

            Database.default = Database(MemoryDriver())
        }

        describe("protected endpoints") {

            let nextResponder = TestResponder()

            var middleware: JWTAuthentication!
            var request: Request!
            var user: Habit.User!

            func accessProtectedEndpointUsingToken(_ token: String) {
                do {
                    request = try Request(headers: ["Authorization": "Bearer \(token)"])
                    _ = try middleware.respond(to: request, chainingTo: nextResponder)
                } catch {
                    print(error)
                }
            }

            func getUser() throws {
                user = try request.user()
            }

            beforeEach {
                middleware = JWTAuthentication(turnstile: .testTurnstile)
                middleware.jwtKey = jwtKey
            }

            describe("invalid token") {

                beforeEach {
                    accessProtectedEndpointUsingToken("invalid")
                }

                it("does not log in user") {
                    expect(error(from: getUser) as? AuthError) == .notAuthenticated
                }
            }

            describe("valid user") {

                beforeEach {
                    register(username: name, password: password)
                    accessProtectedEndpointUsingToken(token)
                    try? getUser()
                }

                it("logs in user") {
                    expect(user).toNot(beNil())
                }
            }
        }

        describe("auth endpoints") {

            describe("login") {

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
}
