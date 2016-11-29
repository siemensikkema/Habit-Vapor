import Auth
import Foundation
import HTTP
import Vapor
import VaporJWT

struct Email: ValidationSuite, Validatable {
    let value: String

    public static func validate(input value: Email) throws {
        try Vapor.Email.validate(input: value.value)
    }
}

struct Username: ValidationSuite, Validatable {
    let value: String

    public static func validate(input value: Username) throws {
        let evaluation = OnlyAlphanumeric.self
            && Count.min(2)
            && Count.max(50)

        try evaluation.validate(input: value.value)
    }
}

public final class User: Model {
    typealias Secret = String
    typealias Salt = String

    struct Constants {
        static let email = "email"
        static let id = "id"
        static let username = "username"
        static let lastPasswordUpdate = "last_password_update"
        static let salt = "salt"
        static let secret = "secret"
    }

    public var exists = false
    public var id: Node?

    var email: Email
    var username: Username
    fileprivate var secret: Secret
    fileprivate var salt: Salt
    fileprivate var lastPasswordUpdate: Date

    convenience init(email: Valid<Email>, username: Valid<Username>, salt: Salt, secret: Secret) {
        self.init(email: email,
                  username: username,
                  salt: salt,
                  secret: secret,
                  lastPasswordUpdate: Date())
    }

    init(email: Valid<Email>,
         username: Valid<Username>,
         salt: Salt,
         secret: Secret,
         lastPasswordUpdate: Date) {
        self.email = email.value
        self.lastPasswordUpdate = lastPasswordUpdate
        self.username = username.value
        self.salt = salt
        self.secret = secret
    }

    // NodeInitializable
    public init(node: Node, in context: Context) throws {
        email = Email(value: try node.extract(Constants.email))
        id = try node.extract(Constants.id)
        username = Username(value: try node.extract(Constants.username))
        lastPasswordUpdate = try node.extract(Constants.lastPasswordUpdate,
                                              transform: Date.init(timeIntervalSince1970:))
        salt = try node.extract(Constants.salt)
        secret = try node.extract(Constants.secret)
    }

    static func find(by email: Email) throws -> User? {
        return try User.query().filter(Constants.email, email.value).first()
    }
}

// ResponseRepresentable
extension User {
    public func makeResponse() throws -> Response {
        return try JSON([
            Constants.username: .string(username.value),
            Constants.email: .string(email.value)])
            .makeResponse()
    }
}

// NodeRepresentable
extension User {
    public func makeNode(context: Context) throws -> Node {
        return try Node(node: [
            Constants.email: email.value,
            Constants.id: id,
            Constants.username: username.value,
            Constants.lastPasswordUpdate: lastPasswordUpdate.timeIntervalSince1970,
            Constants.salt: salt,
            Constants.secret: secret
            ])
    }
}

// Preparation
extension User {
    public static func prepare(_ database: Database) throws {
        try database.create(entity) { users in
            users.id()
            users.double(Constants.lastPasswordUpdate)
            users.string(Constants.email)
            users.string(Constants.username)
            users.string(Constants.salt)
            users.string(Constants.secret)
        }
    }

    public static func revert(_ database: Database) throws {
        try database.delete(entity)
    }
}

extension User: Auth.User {
    public static func authenticate(credentials: Credentials) throws -> Auth.User {
        switch credentials {
        case let node as Node:
            return try node.user()
        case let userCredentials as UserCredentials:
            return try userCredentials.user()
        default:
            let type = type(of: credentials)
            throw Abort.custom(status: .forbidden, message: "Unsupported credential type: \(type).")
        }
    }

    public static func register(credentials: Credentials) throws -> Auth.User {
        throw Abort.custom(status: .notImplemented, message: "")
    }
}

extension User {
    func update(hashedPassword: HashedPassword, now: Date) {
        lastPasswordUpdate = now
        salt = hashedPassword.salt
        secret = hashedPassword.secret
    }
}

extension User: Storable {
    public var node: Node {
        return [Constants.id: Node(id?.int ?? -1),
                Constants.lastPasswordUpdate: Node(Int(lastPasswordUpdate.timeIntervalSince1970))]
    }
}

extension Request {
    func user() throws -> User {
        guard let user = try auth.user() as? User else {
            throw Abort.custom(status: .badRequest, message: "Invalid user type.")
        }
        
        return user
    }
}

extension Node {
    fileprivate func user() throws -> User {
        guard
            let userInfo: Node = try extract(User.name),
            let id: String = try userInfo.extract(User.Constants.id),
            let lastPasswordUpdate: Int = try userInfo.extract(User.Constants.lastPasswordUpdate)
            else {
                throw HabitError.couldNotLogIn
        }

        guard let user = try User.find(id) else {
            throw Abort.custom(status: .badRequest, message: "User not found")
        }

        guard Int(user.lastPasswordUpdate.timeIntervalSince1970) <= Int(lastPasswordUpdate) else {
            throw Abort.custom(status: .forbidden, message: "Incorrect password")
        }

        return user
    }
}

extension UserCredentials {
    fileprivate func user() throws -> User {
        guard
            let user = try User.find(by: email),
            try hashPassword(using: user.salt).secret == user.secret else {
                throw Abort.custom(status: .badRequest,
                                   message: "User not found or incorrect password")
        }
        return user
    }
}
