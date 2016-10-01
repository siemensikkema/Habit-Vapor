import Auth
import Cache
import Foundation
import HTTP
import JWT
import Turnstile
import Vapor

public final class JWTAuthentication: Middleware {

    private let turnstile: Turnstile

    public var jwtKey: Data!

    init(turnstile: Turnstile) {
        self.turnstile = turnstile
    }

    public convenience init<U: Auth.User>(
        user: U.Type = U.self,
        realm: Realm = AuthenticatorRealm(U.self),
        cache: CacheProtocol = MemoryCache()) {
        let sessionManager = CacheSessionManager(cache: cache, realm: realm)
        let turnstile = Turnstile(sessionManager: sessionManager, realm: realm)
        self.init(turnstile: turnstile)
    }

    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let subject = Subject(turnstile: turnstile)
        request.storage["subject"] = subject

        do {
            if  let jwt = request.auth.header?.bearer?.string,
                let credentials = AuthenticatedUserCredentials(
                    payload: try decode(jwt, algorithm: .hs256(jwtKey))) {

                try subject.login(credentials: credentials, persist: false)
            }
        } catch {
            print(error)
            // do nothing, failed login will be handled by ProtectMiddleware
        }

        return try next.respond(to: request)
    }
}

struct AuthenticatedUserCredentials: Credentials {
    let id: String
    let lastPasswordUpdate: Date

    init?(payload: Payload) {
        guard
            let id: String = payload[User.Constants.id],
            let lastPasswordUpdate: Date = payload[User.Constants.lastPasswordUpdate] else {
                return nil
        }

        self.id = id
        self.lastPasswordUpdate = lastPasswordUpdate
    }
}
