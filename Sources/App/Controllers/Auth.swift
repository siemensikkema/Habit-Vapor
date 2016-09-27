import Auth
import Foundation
import HTTP
import JWT
import Punctual
import TurnstileCrypto
import Vapor

final class AuthController {
	let hash: HashProtocol
	let jwtKey: Data

	init(drop: Droplet, path: String) {
		guard let jwtKey = drop.config.data(for: AppKey.jwt) else {
			fatalError("JWT key is missing")
		}
		self.jwtKey = jwtKey
		hash = drop.hash

		drop.group(path) {
			$0.post("login", handler: login)
			$0.post("register", handler: register)
		}
	}

	func login(_ request: Request) throws -> ResponseRepresentable {
		let authenticator = try Authenticator(request: request, hash: hash)
		try request.auth.login(authenticator, persist: false)

		guard let userId = try request.user().id?.string else {
			print("Invalid user id")
			throw Abort.serverError
		}

		let token = JWT.encode(.hs256(jwtKey)) { builder in
			builder.expiration = Date() + 10.minutes
			builder.issuedAt = Date()
			builder["id"] = userId
		}

		return token
	}

	func register(_ request: Request) throws -> ResponseRepresentable {
		let authenticator = try Authenticator(request: request, hash: hash)
		var user = try authenticator.user()
		try user.save()
		return user
	}
}

struct Authenticator: Credentials {
	typealias Password = String

	let username: User.Name
	private let hash: HashProtocol
	private let password: Password

	init(request: Request, hash: HashProtocol) throws {
		guard
			let username = request.data["username"]?.string,
			let password = request.data["password"]?.string else {
				throw Abort.badRequest
		}

		self.hash = hash
		self.username = username
		self.password = password
	}

	func secret(salt: User.Salt) throws -> User.Secret {
		return try hash.make(password + salt)
	}

	func user() throws -> User {
		let salt = BCryptSalt().string
		return User(name: username, salt: salt, secret: try secret(salt: salt))
	}
}
