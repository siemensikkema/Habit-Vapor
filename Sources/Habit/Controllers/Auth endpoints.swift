import Auth
import Core
import Foundation
import HTTP
import Punctual
import TurnstileCrypto
import Vapor
import VaporJWT

public final class AuthController {
    typealias CreateUser = (Valid<Email>, Valid<Username>, User.Salt, User.Secret) -> User
    typealias SaveUser = (inout User) throws -> Void

    private let hash: HashProtocol
    private let jwtKey: Bytes
    private let createUser: CreateUser
    private let saveUser: SaveUser

    // used for testing
    private let issueDate: Date?
    private let passwordUpdate: Date?

    public convenience init(jwtKey: Bytes, hash: HashProtocol) {
        self.init(jwtKey: jwtKey,
                  hash: hash,
                  createUser: User.init(email:username:salt:secret:),
                  saveUser: { try $0.save() })
    }

    init(jwtKey: Bytes,
         hash: HashProtocol,
         issueDate: Date? = nil,
         passwordUpdate: Date? = nil,
         createUser: @escaping CreateUser,
         saveUser: @escaping SaveUser) {
        self.hash = hash
        self.jwtKey = jwtKey

        self.issueDate = issueDate
        self.passwordUpdate = passwordUpdate

        self.createUser = createUser
        self.saveUser = saveUser
    }

    private func extractValues(_ data: Content) throws ->
        (email: Email, username: Username?, password: Password, newPassword: Password?) {
        guard let email = data["email"]?.string.map(Email.init) else {
            throw Abort.custom(status: .badRequest, message: "Email is missing")
        }
        guard let password = data["password"]?.string.map(Password.init) else {
            throw Abort.custom(status: .badRequest, message: "Password is missing")
        }
        let username = data["username"]?.string.map(Username.init)
        let newPassword = data["new_password"]?.string.map(Password.init)
        return (email, username, password, newPassword)
    }

    public func logIn(_ request: Request) throws -> ResponseRepresentable {
        let values = try extractValues(request.data)
        let credentials = UserCredentials(email: values.email,
                                          password: values.password,
                                          hash: hash)
        try request.auth.login(credentials, persist: false)
        let user = try request.user()

        return try token(user: user)
    }

    public func signUp(_ request: Request) throws -> ResponseRepresentable {
        let values = try extractValues(request.data)
        guard let username: Valid<Username> = try values.username?.validated() else {
            throw Abort.custom(status: .badRequest, message: "Username is missing")
        }
        let email: Valid<Email> = try values.email.validated()
        let password: Valid<Password> = try values.password.validated()

        guard let userExists = try? User.find(by: email.value) != nil,
            userExists == false else {
                throw Abort.custom(status: .badRequest, message: "User exists")
        }

        let credentials = UserCredentials(email: email.value,
                                          password: password.value,
                                          hash: hash)
        let hashedPassword = try credentials.hashPassword()
        var user = createUser(email, username, hashedPassword.salt, hashedPassword.secret)
        try saveUser(&user)

        return try token(user: user)
    }

    public func updatePassword(_ request: Request) throws -> ResponseRepresentable {
        let values = try extractValues(request.data)

        guard let newPassword: Valid<Password> = try values.newPassword?.validated() else {
            throw Abort.badRequest
        }
        guard newPassword.value != values.password else {
            throw Abort.custom(status: .badRequest, message: "New password must be different")
        }
        let credentials = UserCredentials(email: values.email,
                                          password: values.password,
                                          hash: hash)
        try request.auth.login(credentials, persist: false)
        var user = try request.user()

        let (salt, secret) = try credentials.hashPassword(newPassword)
        user.update(salt: salt, secret: secret, now: passwordUpdate ?? Date())
        try saveUser(&user)

        return try token(user: user)
    }

    private func token(user: User) throws -> String {
        let now = issueDate ?? Date()
        guard
            let expirationDate = 10.minutes.from(now) else {
                throw Abort.serverError
        }

        let jwt = try JWT(payload: Node([ExpirationTimeClaim(expirationDate), user]),
                          signer: HS256(key: jwtKey))

        return try jwt.createToken()
    }
}

struct Password: Validatable, ValidationSuite, Equatable {
    let value: String

    public static func validate(input value: Password) throws {
        try Count.min(8).validate(input: value.value)
    }

    static func == (lhs: Password, rhs: Password) -> Bool {
        return lhs.value == rhs.value
    }
}

struct UserCredentials: Credentials {
    let email: Email
    private let hash: HashProtocol
    private let password: Password

    init(email: Email, password: Password, hash: HashProtocol) {
        self.email = email
        self.hash = hash
        self.password = password
    }

    typealias HashedPassword = (secret: User.Secret, salt: User.Salt)

    /// Hashes password using salt
    ///
    /// - parameter providedPassword: password to hash or nil to use existing password
    /// - parameter salt:             salt to use while hashing or nil to create new random salt
    ///
    /// - throws: when hashing fails
    ///
    /// - returns: salt and hashed password
    func hashPassword(_ providedPassword: Valid<Password>? = nil,
                      using salt: User.Salt = BCryptSalt().string) throws -> HashedPassword {
        return (try hash.make((providedPassword?.value.value ?? password.value) + salt), salt)
    }
}
