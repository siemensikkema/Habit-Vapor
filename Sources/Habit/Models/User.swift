import Auth
import Foundation
import HTTP
import JWT
import Vapor

public final class User: Model {
    typealias Name = String
    typealias Secret = String
    typealias Salt = String

    fileprivate struct Constants {
        static let id = "id"
        static let name = "name"
        static let lastPasswordUpdate = "last_password_update"
        static let salt = "salt"
        static let secret = "secret"
    }

    public var exists = false
    public var id: Node?

    var name: Name
    fileprivate var secret: Secret
    fileprivate var salt: Salt
    fileprivate var lastPasswordUpdate: Date

    convenience init(name: Name, salt: Salt, secret: Secret) {
        self.init(name: name, salt: salt, secret: secret, lastPasswordUpdate: Date())
    }

    init(name: Name, salt: Salt, secret: Secret, lastPasswordUpdate: Date) {
        self.lastPasswordUpdate = lastPasswordUpdate
        self.name = name
        self.salt = salt
        self.secret = secret
    }

    // NodeInitializable
    public init(node: Node, in context: Context) throws {
        id = try node.extract(Constants.id)
        name = try node.extract(Constants.name)
        lastPasswordUpdate = try node.extract(Constants.lastPasswordUpdate,
                                              transform: Date.init(timeIntervalSince1970:))
        salt = try node.extract(Constants.salt)
        secret = try node.extract(Constants.secret)
    }
}

// ResponseRepresentable
extension User {
    public func makeResponse() throws -> Response {
        var node = try makeNode()

        // make sure credential related information stay secret
        node[Constants.lastPasswordUpdate] = nil
        node[Constants.secret] = nil
        node[Constants.salt] = nil

        return try JSON(node).makeResponse()
    }
}

// NodeRepresentable
extension User {
    public func makeNode(context: Context) throws -> Node {
        return try Node(node: [
            Constants.id: id,
            Constants.name: name,
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
            guard user.lastPasswordUpdate <= credentials.lastPasswordUpdate else {
                throw Abort.custom(status: .forbidden, message: "Incorrect password")
            }
            authenticatedUser = user

        case let credentials as UserCredentials:
            guard
                let user = try User.query().filter(Constants.name, credentials.username).first(),
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
    func update(salt: Salt, secret: Secret) {
        lastPasswordUpdate = Date()
        self.salt = salt
        self.secret = secret
    }

    var payload: Payload {
        var payload = Payload()
        payload["id"] = id?.string
        payload["last_password_update"] = lastPasswordUpdate
        return payload
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
