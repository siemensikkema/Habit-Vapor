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
            try request.auth.login(payload, persist: false)
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

extension Node: Credentials {}
