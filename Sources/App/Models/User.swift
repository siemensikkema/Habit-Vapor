import Auth
import HTTP
import Vapor

final class User: Model {
	typealias Name = String
	typealias Secret = String
	typealias Salt = String

	fileprivate struct Constants {
		static let id = "id"
		static let name = "name"
		static let salt = "salt"
		static let secret = "secret"
	}

	var exists = false
	var id: Node?

	var name: Name
	fileprivate var secret: Secret
	fileprivate var salt: Salt

	init(name: Name, salt: Salt, secret: Secret) {
		self.name = name
		self.salt = salt
		self.secret = secret
	}

	// NodeInitializable
	init(node: Node, in context: Context) throws {
		id = try node.extract(Constants.id)
		name = try node.extract(Constants.name)
		salt = try node.extract(Constants.salt)
		secret = try node.extract(Constants.secret)
	}
}

// ResponseRepresentable
extension User {
	public func makeResponse() throws -> Response {
		var node = try makeNode()

		// make sure secret and salt stay secret
		node[Constants.secret] = nil
		node[Constants.salt] = nil

		return try JSON(node).makeResponse()
	}
}

// NodeRepresentable
extension User {
	func makeNode(context: Context) throws -> Node {
		return try Node(node: [
			Constants.id: id,
			Constants.name: name,
			Constants.salt: salt,
			Constants.secret: secret
			])
	}
}

// Preparation
extension User {
	static func prepare(_ database: Database) throws {
		try database.create(entity) { users in
			users.id()
			users.string(Constants.name)
			users.string(Constants.salt)
			users.string(Constants.secret)
		}
	}

	static func revert(_ database: Database) throws {
		try database.delete(entity)
	}
}

extension User: Auth.User {
	static func authenticate(credentials: Credentials) throws -> Auth.User {
		let authenticatedUser: User

		switch credentials {
		case let id as Identifier:
			guard let user = try User.find(id.id) else {
				throw Abort.custom(status: .badRequest, message: "User not found")
			}
			authenticatedUser = user

		case let authenticator as Authenticator:
			guard
				let user = try User.query().filter(Constants.name, authenticator.username).first(),
				try authenticator.createCredential(salt: user.salt).secret == user.secret else {
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

	static func register(credentials: Credentials) throws -> Auth.User {
		throw Abort.custom(status: .notImplemented, message: "")
	}
}

extension User {
	func update(salt: Salt, secret: Secret) {
		self.salt = salt
		self.secret = secret
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
