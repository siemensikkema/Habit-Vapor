import Auth
import Cache
import Core
import Foundation
import HTTP
import Turnstile
import Vapor
import VaporJWT

public final class JWTAuthentication: Middleware {
    private let jwtKey: Bytes
    private let turnstile: Turnstile

    init(jwtKey: Bytes, turnstile: Turnstile) {
        self.jwtKey = jwtKey
        self.turnstile = turnstile
    }

    public convenience init<U: Auth.User>(
        jwtKey: Bytes,
        user: U.Type = U.self,
        realm: Realm = AuthenticatorRealm(U.self),
        cache: CacheProtocol = MemoryCache()) {
        let sessionManager = CacheSessionManager(cache: cache, realm: realm)
        let turnstile = Turnstile(sessionManager: sessionManager, realm: realm)
        self.init(jwtKey: jwtKey, turnstile: turnstile)
    }

    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let subject = Subject(turnstile: turnstile)
        request.storage["subject"] = subject

        do {
            let credentials = try getVerifiedCredentials(request: request)
            try subject.login(credentials: credentials, persist: false)
        } catch {
            print(error)
            // do nothing, failed login will be handled by ProtectMiddleware
        }

        return try next.respond(to: request)
    }

    private func getVerifiedCredentials(request: Request) throws -> Credentials {
        guard
            let jwt = try request.auth.header?.bearer.map({ try JWT(token: $0.string) }),
            let credentials = try AuthenticatedUserCredentials(node: jwt.payload.node),
            try jwt.verifySignatureWith(HS256(key: jwtKey)),
            jwt.verifyClaims([ExpirationTimeClaim()]) else {
                throw HabitError.couldNotLogIn
        }
        return credentials
    }
}

struct AuthenticatedUserCredentials: Credentials {
    let id: String
    let lastPasswordUpdate: Date
}

extension AuthenticatedUserCredentials {
    init?(node: Node) throws {
        guard
            let user: Node = try node.extract(User.name),
            let id: String = try user.extract(User.Constants.id),
            let lastPasswordUpdate: Int = try user.extract(User.Constants.lastPasswordUpdate) else {
                return nil
        }

        self.id = id
        self.lastPasswordUpdate = Date(timeIntervalSince1970: TimeInterval(lastPasswordUpdate))
    }
}
