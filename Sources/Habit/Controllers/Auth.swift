import Auth
import Foundation
import HTTP
import JWT
import Punctual
import TurnstileCrypto
import Vapor

public final class AuthController {

    typealias CreateUser = (Valid<Name>, User.Salt, User.Secret) -> User
    typealias SaveUser = (inout User) throws -> Void

    private let hash: HashProtocol
    private let jwtKey: Data
    private let createUser: CreateUser
    private let saveUser: SaveUser
    private let issueDate: Date? // used for testing

    public convenience init(jwtKey: Data, hash: HashProtocol) {
        self.init(jwtKey: jwtKey,
                  hash: hash,
                  createUser: User.init(name:salt:secret:),
                  saveUser: { try $0.save() })
    }

    init(jwtKey: Data,
         hash: HashProtocol,
         issueDate: Date? = nil,
         createUser: @escaping CreateUser,
         saveUser: @escaping SaveUser) {
        self.hash = hash
        self.jwtKey = jwtKey
        self.issueDate = issueDate

        self.createUser = createUser
        self.saveUser = saveUser
    }

    private func extractValues(_ data: Content) throws ->
        (username: Name, password: Password, newPassword: Password?) {
        guard
            let username = data["username"]?.string.map(Name.init),
            let password = data["password"]?.string.map(Password.init) else {
                throw Abort.badRequest
        }
        let newPassword = data["new_password"]?.string.map(Password.init)
        return (username, password, newPassword)
    }

    public func logIn(_ request: Request) throws -> ResponseRepresentable {
        let values = try extractValues(request.data)
        let credentials = UserCredentials(username: values.username,
                                          password: values.password,
                                          hash: hash)
        try request.auth.login(credentials, persist: false)
        let user = try request.user()

        return try token(user: user)
    }

    public func register(_ request: Request) throws -> ResponseRepresentable {
        let values = try extractValues(request.data)
        let validUsername: Valid<Name> = try values.username.validated()
        let validPassword: Valid<Password> = try values.password.validated()

        guard let userExists = try? User.findByName(validUsername.value) != nil,
            userExists == false else {
                throw Abort.custom(status: .badRequest, message: "User exists")
        }

        let credentials = UserCredentials(username: validUsername.value,
                                          password: validPassword.value,
                                          hash: hash)
        let hashedPassword = try credentials.hashPassword()
        var user = createUser(validUsername, hashedPassword.salt, hashedPassword.secret)
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
        let credentials = UserCredentials(username: values.username,
                                          password: values.password,
                                          hash: hash)
        try request.auth.login(credentials, persist: false)
        var user = try request.user()

        let (salt, secret) = try credentials.hashPassword(newPassword)
        user.update(salt: salt, secret: secret)
        try saveUser(&user)

        return try token(user: user)
    }

    private func token(user: User) throws -> String {
        do {
            var payload = user.payload
            let now = self.issueDate ?? Date()
            payload.expiration = 10.minutes.from(now)
            payload.issuedAt = now
            return try encode(payload, algorithm: .hs256(jwtKey))
        } catch {
            print(error.localizedDescription)
            throw Abort.serverError
        }
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
