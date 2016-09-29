import Auth
import Cache
import Foundation
import HTTP
import JWT
import Turnstile
import Vapor

final class BearerAuthMiddleware: Middleware {
	private let turnstile: Turnstile

	var config: Config? {
		didSet {
			jwtData = config?.data(for: AppKey.jwt)
		}
	}
	var jwtData: Data!

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

		if  let jwt = request.auth.header?.bearer?.string,
            let payload = try? decode(jwt, algorithm: .hs256(jwtData)),
            let credentials = AuthenticatedUserCredentials(payload: payload) {

			do {
				try subject.login(credentials: credentials, persist: false)
			} catch {
                print(error)
				// do nothing, failed login will be handled by ProtectMiddleware
			}
		}

		let response = try next.respond(to: request)

		return response
	}
}

struct AuthenticatedUserCredentials: Credentials {
    let id: String
    let lastPasswordUpdate: Date

    init?(payload: Payload) {
        guard let id: String = payload["id"], let lastPasswordUpdate: Date = payload["last_password_reset"] else {
            return nil
        }

        self.id = id
        self.lastPasswordUpdate = lastPasswordUpdate
    }
}
