import Auth
import Cache
import Foundation
import HTTP
import JWT
import Turnstile
import Vapor

final class BearerAuthMiddleware: Middleware {
	private let turnstile: Turnstile

	var jwtData: Data?
	var config: Config? {
		didSet {
			jwtData = config?.data(for: AppKey.jwt)
		}
	}

	init(turnstile: Turnstile) {
		self.turnstile = turnstile
	}

	convenience init<U: Auth.User>(
		user: U.Type = U.self,
		realm: Realm = AuthenticatorRealm(U.self),
		cache: CacheProtocol = MemoryCache()
	) {
		let session = CacheSessionManager(cache: cache, realm: realm)
		let turnstile = Turnstile(sessionManager: session, realm: realm)
		self.init(turnstile: turnstile)
	}

	func respond(to request: Request, chainingTo next: Responder) throws -> Response {
		let subject = Subject(turnstile: turnstile)
		request.storage["subject"] = subject

		if let jwt = request.auth.header?.bearer?.string, let jwtData = jwtData {

			do {
				let payload = try JWT.decode(jwt, algorithm: .hs256(jwtData))
				if let identifierString = payload["id"] as? String {
					let identifier = Identifier(id: Node.string(identifierString))
					try subject.login(credentials: identifier, persist: false)
				}
			} catch {
				// do nothing, failed login will be caught by ProtectMiddleware
			}
		}

		let response = try next.respond(to: request)

		return response
	}
}
