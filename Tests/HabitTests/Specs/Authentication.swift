@testable import Habit
import Auth
import Essentials
import Fluent
import Foundation
import HTTP
import VaporJWT
import Nimble
import Punctual
import Quick
import Vapor

extension Habit.User {
    static let testEmail = "elon@spacex.com"
    static let testPassword = "g0t0m@rs"
    static let testName = "ElonMusk"

    static func testUser(name: String = testName,
                         email: String = testEmail,
                         password: String = testPassword,
                         date: Date = Date()) -> Habit.User {
        return Habit.User(email: try! Email(value: testEmail).validated(),
                          name: try! Name(value: testName).validated(),
                          salt: "",
                          secret: testPassword.bytes.hexString,
                          lastPasswordUpdate: date)
    }
}

final class AuthenticationSpec: QuickSpec {
    override func spec() {
        
        // initializing date this way enables comparison
        let date = Date(timeIntervalSince1970: Date().timeIntervalSince1970)
        let hasher = TestHasher()
        let jwtKey = "secret".bytes

        var error: Error?
        var controller: AuthController!
        var jwt: JWT!
        var token: String!

        var userWasSaved = false

        func createPayload(passwordUpdate: Date? = nil) -> Node {
            return [
                "exp": Node(Int(10.minutes.from(date)!.timeIntervalSince1970)),
                "user": Node([
                    "id": Node(1),
                    "last_password_update":
                        Node(Int((passwordUpdate ?? date).timeIntervalSince1970))])]
        }

        func createUser() {
            do {
                var user = User.testUser(date: date)
                try user.save()
            } catch {
                print(error)
            }
        }

        func parseResponse(_ response: ResponseRepresentable) {
            guard let responseToken = response as? String else {
                return
            }
            do {
                token = responseToken
                jwt = try JWT(token: token)
            } catch {
                print(error)
            }
        }

        func performAction(_ action: (Request) throws -> ResponseRepresentable,
                           with parameters: [String: String]) {
            do {
                let request = try Request(body: parameters)
                parseResponse(try action(request))
            } catch let e {
                error = e
            }
        }

        func logInUserWithName(_ name: String, password: String) {
            performAction(controller.logIn, with: ["name": name, "password": password])
        }

        func registerUserWithEmail(_ email: String, name: String, password: String) {
            performAction(controller.register,
                          with: ["email": email, "name": name, "password": password])
        }

        func updatePassword(_ password: String,
                            to newPassword: String,
                            forUserWithName name: String) {
            performAction(controller.updatePassword,
                          with: ["name": name, "password": password, "new_password": newPassword])
        }

        beforeEach {
            controller = AuthController(
                jwtKey: jwtKey,
                hash: hasher,
                issueDate: date,
                passwordUpdate: date + 1,
                createUser: { (email, name, salt, secret) in
                    User(email: email,
                         name: name,
                         salt: salt,
                         secret: secret,
                         lastPasswordUpdate: date)
                },
                saveUser: { (user) in
                    try user.save()
                    userWasSaved = true
            })
            Database.default = Database(MemoryDriver())
        }

        afterEach {
            error = nil
            jwt = nil
            token = nil
            userWasSaved = false
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
                middleware = JWTAuthentication(jwtKey: jwtKey, turnstile: .testTurnstile)
            }

            describe("invalid token") {
                beforeEach {
                    accessProtectedEndpointUsingToken("invalid")
                }

                it("does not log in user") {
                    expect(catchError(from: getUser) as? AuthError) == .notAuthenticated
                }
            }

            fdescribe("valid user") {
                beforeEach {
                    registerUserWithEmail(User.testEmail,
                                          name: User.testName,
                                          password: User.testPassword)
                    accessProtectedEndpointUsingToken(token)

                    do {
                        try getUser()
                    } catch {
                        print(error)
                    }
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
                        logInUserWithName(User.testName, password: User.testPassword)
                    }

                    it("fails") {
                        expect(error as? Abort) == .custom(
                            status: .badRequest,
                            message: "User not found or incorrect password")
                    }
                }

                context("incorrect password") {
                    beforeEach {
                        createUser()
                        logInUserWithName(User.testName, password: "")
                    }

                    it("fails") {
                        expect(error as? Abort) == .custom(
                            status: .badRequest,
                            message: "User not found or incorrect password")
                    }
                }

                context("correct password") {
                    beforeEach {
                        createUser()
                        logInUserWithName(User.testName, password: User.testPassword)
                    }

                    it("succeeds") {
                        expect(error).to(beNil())
                    }

                    describe("token") {
                        it("contains expected payload") {
                            expect(jwt.payload) == createPayload()
                        }

                        it ("has correct signature") {
                            expect(try? jwt.verifySignatureWith(HS256(key: jwtKey))) == true
                        }
                    }
                }
            }

            describe("register") {
                context("new and valid user") {
                    beforeEach {
                        registerUserWithEmail(User.testEmail,
                                              name: User.testName,
                                              password: User.testPassword)
                    }

                    it("succeeds") {
                        expect(error).to(beNil())
                    }

                    it("saves user") {
                        expect(userWasSaved) == true
                    }

                    describe("token") {
                        it("contains expected payload") {
                            expect(jwt.payload) == createPayload()
                        }

                        it ("has correct signature") {
                            expect(try? jwt.verifySignatureWith(HS256(key: jwtKey))) == true
                        }
                    }
                }

                context("existing user") {
                    beforeEach {
                        createUser()
                        registerUserWithEmail(User.testEmail,
                                              name: User.testName,
                                              password: User.testPassword)
                    }

                    it("fails") {
                        expect(error as? Abort) == .custom(status: .badRequest,
                                                           message: "User exists")
                    }

                    it("does not save user") {
                        expect(userWasSaved) == false
                    }
                }

                context("missing email") {
                    beforeEach {
                        performAction(
                            controller.register,
                            with: ["name": User.testName, "password": User.testPassword])
                    }

                    it("fails") {
                        expect(error as? Abort) == .custom(status: .badRequest,
                                                           message: "Email is missing")
                    }
                }

                context("invalid email") {
                    beforeEach {
                        registerUserWithEmail("", name: User.testName, password: User.testEmail)
                    }

                    it("fails") {
                        expect(error as? ValidationErrorProtocol).toNot(beNil())
                    }
                }

                context("missing name") {
                    beforeEach {
                        performAction(
                            controller.register,
                            with: ["email": User.testName, "password": User.testPassword])
                    }

                    it("fails") {
                        expect(error as? Abort) == .custom(status: .badRequest,
                                                           message: "Name is missing")
                    }
                }

                context("invalid name") {
                    beforeEach {
                        registerUserWithEmail(User.testEmail, name: "", password: User.testPassword)
                    }

                    it("fails") {
                        expect(error as? ValidationErrorProtocol).toNot(beNil())
                    }
                }

                context("invalid password") {
                    beforeEach {
                        registerUserWithEmail(User.testEmail, name: User.testName, password: "")
                    }

                    it("fails") {
                        expect(error as? ValidationErrorProtocol).toNot(beNil())
                    }
                }

                context("missing password") {
                    beforeEach {
                        performAction(
                            controller.register,
                            with: ["email": User.testName, "name": User.testName])
                    }

                    it("fails") {
                        expect(error as? Abort) == .custom(status: .badRequest,
                                                           message: "Password is missing")
                    }
                }
            }

            describe("update password") {
                context("same password") {
                    beforeEach {
                        updatePassword(User.testPassword,
                                       to: User.testPassword,
                                       forUserWithName: User.testName)
                    }

                    it("fails") {
                        expect(error as? Abort) == .custom(
                            status: .badRequest,
                            message: "New password must be different")
                    }
                    
                    it("does not save user") {
                        expect(userWasSaved) == false
                    }
                }
                
                context("different password") {
                    beforeEach {
                        createUser()
                        updatePassword(User.testPassword,
                                       to: "\(User.testPassword)2",
                                       forUserWithName: User.testName)
                    }
                    
                    it("succeeds") {
                        expect(error).to(beNil())
                    }
                    
                    it("saves user") {
                        expect(userWasSaved) == true
                    }
                    
                    describe("token") {
                        it("contains expected payload") {
                            expect(jwt.payload) == createPayload(passwordUpdate: date + 1)
                        }

                        it ("has correct signature") {
                            expect(try? jwt.verifySignatureWith(HS256(key: jwtKey))) == true
                        }
                    }

                    context("invalid new password") {
                        beforeEach {
                            updatePassword(User.testPassword,
                                           to: "",
                                           forUserWithName: User.testName)
                        }
                        
                        it("fails") {
                            expect(error as? ValidationErrorProtocol).toNot(beNil())
                        }
                    }
                }
            }
        }
    }
}
