import Auth
import HTTP
import Node
import VaporJWT

public final class JWTMiddleware: Middleware {
    private let signer: Signer

    public init(jwtKey: Bytes) {
        signer = HS256(key: jwtKey)
    }

    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        if let accessToken = request.auth.header?.bearer {
            let payload = try getVerifiedJWTPayload(from: accessToken)
            let authenticatedUserCredentials = try AuthenticatedUserCredentials(node: payload)
            try request.auth.login(authenticatedUserCredentials, persist: false)
        }
        return try next.respond(to: request)
    }

    private func getVerifiedJWTPayload(from accessToken: AccessToken) throws -> Node {
        let jwt = try JWT(token: accessToken.string)
        guard try jwt.verifySignatureWith(signer) else {
            throw HabitError.couldNotVerifySignature
        }
        guard jwt.verifyClaims([ExpirationTimeClaim()]) else {
            throw HabitError.couldNotVerifyClaims
        }
        return jwt.payload
    }
}

struct AuthenticatedUserCredentials: Credentials {
    let id: String
    let lastPasswordUpdate: Int

    init(node: Node) throws {
        guard
            let userInfo: Node = try node.extract(User.name),
            let id: String = try userInfo.extract(User.Constants.id),
            let lastPasswordUpdate: Int = try userInfo.extract(User.Constants.lastPasswordUpdate)
            else {
                throw HabitError.couldNotLogIn
        }

        self.id = id
        self.lastPasswordUpdate = lastPasswordUpdate
    }
}
