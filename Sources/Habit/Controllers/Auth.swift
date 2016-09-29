import Auth
import Foundation
import HTTP
import JWT
import Punctual
import TurnstileCrypto
import Vapor

public final class AuthController {

    typealias CreateUser = (User.Name, User.Salt, User.Secret) -> User
    typealias SaveUser = (inout User) throws -> Void

    private let hash: HashProtocol
    private let jwtKey: Data
    private let createUser: CreateUser
    private let saveUser: SaveUser

    public convenience init(jwtKey: Data, hash: HashProtocol) {
        self.init(jwtKey: jwtKey, hash: hash, createUser: User.init(name:salt:secret:), saveUser: { try $0.save() })
    }

    init(jwtKey: Data,
         hash: HashProtocol,
         createUser: @escaping CreateUser,
         saveUser: @escaping SaveUser) {
        self.jwtKey = jwtKey
        self.hash = hash
        self.createUser = createUser
        self.saveUser = saveUser
    }

    public func changePassword(_ request: Request) throws -> ResponseRepresentable {
        guard let newPassword = request.data["new_password"]?.string else {
            throw Abort.badRequest
        }

        let credentials = try UserCredentials(data: request.data, hash: hash)
        try request.auth.login(credentials, persist: false)
        var user = try request.user()

        let (salt, secret) = try credentials.hashPassword(newPassword)
        user.update(salt: salt, secret: secret)
        try saveUser(&user)

        return try token(user: user)
    }

    public func login(_ request: Request) throws -> ResponseRepresentable {
        let credentials = try UserCredentials(data: request.data, hash: hash)
        try request.auth.login(credentials, persist: false)
        let user = try request.user()

        return try token(user: user)
    }

    public func register(_ request: Request) throws -> ResponseRepresentable {
        let credentials = try UserCredentials(data: request.data, hash: hash)
        let hashedPassword = try credentials.hashPassword()
        var user = createUser(credentials.username, hashedPassword.salt, hashedPassword.secret)
        try saveUser(&user)

        return try token(user: user)
    }

    private func token(user: User) throws -> String {
        do {
            return try encode(user.payload, algorithm: .hs256(jwtKey))
        } catch {
            print(error.localizedDescription)
            throw Abort.serverError
        }
    }
}

struct UserCredentials: Credentials {
    typealias Password = String

    let username: User.Name
    private let hash: HashProtocol
    private let password: Password

    init(data: Content, hash: HashProtocol) throws {
        guard
            let username = data["username"]?.string,
            let password = data["password"]?.string else {
                throw Abort.badRequest
        }

        if let newPassword = data["new_password"]?.string, newPassword == password {
            throw Abort.custom(status: .badRequest, message: "New password must be different")
        }

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
    func hashPassword(_ providedPassword: Password? = nil,
                      using salt: User.Salt = BCryptSalt().string) throws -> HashedPassword {
        return (try hash.make((providedPassword ?? password) + salt), salt)
    }
}
