import HTTP

public final class UserController {

    public init() {}

    public func me(_ request: Request) throws -> ResponseRepresentable {
        return try request.user()
    }
}
