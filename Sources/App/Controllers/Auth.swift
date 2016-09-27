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
			$0.post("changePassword", handler: changePassword)
			$0.post("login", handler: login)
			$0.post("register", handler: register)
		}
	}

	func changePassword(_ request: Request) throws -> ResponseRepresentable {
		guard let newPassword = request.data["new_password"]?.string else {
			throw Abort.badRequest
		}

		let authenticator = try Authenticator(request: request, hash: hash)
		try request.auth.login(authenticator, persist: false)
		var user = try request.user()

		let (salt, secret) = try authenticator.createCredential(
			password: newPassword)
		user.update(salt: salt, secret: secret)
		try user.save()

		return token(user: user)
	}

	func login(_ request: Request) throws -> ResponseRepresentable {
		let authenticator = try Authenticator(request: request, hash: hash)
		try request.auth.login(authenticator, persist: false)
		let user = try request.user()

		return token(user: user)
	}

	func token(user: User) -> String {
		return JWT.encode(.hs256(jwtKey)) { builder in
			builder.expiration = 10.minutes.fromNow
			builder.issuedAt = Date()
			builder["id"] = user.id!.string!
		}
	}

	func register(_ request: Request) throws -> ResponseRepresentable {
		let authenticator = try Authenticator(request: request, hash: hash)
		var user = try authenticator.createUser()
		try user.save()

		return token(user: user)
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

	func createCredential(
		salt: User.Salt = BCryptSalt().string,
		password providedPassword: Password? = nil) throws -> (salt: User.Salt, secret: User.Secret) {
		
		return (salt, try hash.make((providedPassword ?? password) + salt))
	}

	func createUser() throws -> User {
		let (salt, secret) = try createCredential()
		return User(name: username, salt: salt, secret: secret)
	}
}
