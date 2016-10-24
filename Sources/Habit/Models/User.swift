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

struct Name: ValidationSuite, Validatable {
    let value: String

    public static func validate(input value: Name) throws {
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
        static let name = "name"
        static let lastPasswordUpdate = "last_password_update"
        static let salt = "salt"
        static let secret = "secret"
    }

    public var exists = false
    public var id: Node?

    var email: Email
    var name: Name
    fileprivate var secret: Secret
    fileprivate var salt: Salt
    fileprivate var lastPasswordUpdate: Date

    convenience init(email: Valid<Email>, name: Valid<Name>, salt: Salt, secret: Secret) {
        self.init(email: email, name: name, salt: salt, secret: secret, lastPasswordUpdate: Date())
    }

    init(email: Valid<Email>,
         name: Valid<Name>,
         salt: Salt,
         secret: Secret,
         lastPasswordUpdate: Date) {
        self.email = email.value
        self.lastPasswordUpdate = lastPasswordUpdate
        self.name = name.value
        self.salt = salt
        self.secret = secret
    }

    // NodeInitializable
    public init(node: Node, in context: Context) throws {
        email = Email(value: try node.extract(Constants.email))
        id = try node.extract(Constants.id)
        name = Name(value: try node.extract(Constants.name))
        lastPasswordUpdate = try node.extract(Constants.lastPasswordUpdate,
                                              transform: Date.init(timeIntervalSince1970:))
        salt = try node.extract(Constants.salt)
        secret = try node.extract(Constants.secret)
    }

    static func findByName(_ name: Name) throws -> User? {
        return try User.query().filter(Constants.name, name.value).first()
    }
}

// ResponseRepresentable
extension User {
    public func makeResponse() throws -> Response {
        return try JSON([
            Constants.name: .string(name.value),
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
            Constants.name: name.value,
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
            users.string(Constants.name)
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
        let authenticatedUser: User

        switch credentials {
        case let credentials as AuthenticatedUserCredentials:
            guard let user = try User.find(credentials.id) else {
                throw Abort.custom(status: .badRequest, message: "User not found")
            }
            guard
                Int(user.lastPasswordUpdate.timeIntervalSince1970) <=
                Int(credentials.lastPasswordUpdate.timeIntervalSince1970) else {
                    throw Abort.custom(status: .forbidden, message: "Incorrect password")
            }
            authenticatedUser = user

        case let credentials as UserCredentials:
            guard
                let user = try User.findByName(credentials.username),
                try credentials.hashPassword(using: user.salt).secret == user.secret else {
                    throw Abort.custom(status: .badRequest,
                                       message: "User not found or incorrect password")
            }
            authenticatedUser = user

        default:
            let type = type(of: credentials)
            throw Abort.custom(status: .forbidden, message: "Unsupported credential type: \(type).")
        }

        return authenticatedUser
    }

    public static func register(credentials: Credentials) throws -> Auth.User {
        throw Abort.custom(status: .notImplemented, message: "")
    }
}

extension User {
    func update(salt: Salt, secret: Secret, now: Date) {
        lastPasswordUpdate = now
        self.salt = salt
        self.secret = secret
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
