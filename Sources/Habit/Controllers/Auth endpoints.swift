import Auth
import Core
import Foundation
import HTTP
import Punctual
import TurnstileCrypto
import Vapor
import VaporJWT

public final class AuthController {
    typealias CreateUser = (Valid<Email>, Valid<Name>, User.Salt, User.Secret) -> User
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
                  createUser: User.init(email:name:salt:secret:),
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
        (email: Email?, name: Name, password: Password, newPassword: Password?) {
        guard let username = data["name"]?.string.map(Name.init) else {
            throw Abort.custom(status: .badRequest, message: "Name is missing")
        }
        guard let password = data["password"]?.string.map(Password.init) else {
            throw Abort.custom(status: .badRequest, message: "Password is missing")
        }
        let email = data["email"]?.string.map(Email.init)
        let newPassword = data["new_password"]?.string.map(Password.init)
        return (email, username, password, newPassword)
    }

    public func logIn(_ request: Request) throws -> ResponseRepresentable {
        let values = try extractValues(request.data)
        let credentials = UserCredentials(username: values.name,
                                          password: values.password,
                                          hash: hash)
        try request.auth.login(credentials, persist: false)
        let user = try request.user()

        return try token(user: user)
    }

    public func register(_ request: Request) throws -> ResponseRepresentable {
        let values = try extractValues(request.data)
        guard let email: Valid<Email> = try values.email?.validated() else {
            throw Abort.custom(status: .badRequest, message: "Email is missing")
        }
        let name: Valid<Name> = try values.name.validated()
        let password: Valid<Password> = try values.password.validated()

        guard let userExists = try? User.findByName(name.value) != nil,
            userExists == false else {
                throw Abort.custom(status: .badRequest, message: "User exists")
        }

        let credentials = UserCredentials(username: name.value,
                                          password: password.value,
                                          hash: hash)
        let hashedPassword = try credentials.hashPassword()
        var user = createUser(email, name, hashedPassword.salt, hashedPassword.secret)
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
        let credentials = UserCredentials(username: values.name,
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
    let username: Name
    private let hash: HashProtocol
    private let password: Password

    init(username: Name, password: Password, hash: HashProtocol) {
        self.hash = hash
        self.username = username
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
