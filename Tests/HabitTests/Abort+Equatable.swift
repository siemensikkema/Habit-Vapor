import Vapor

extension Abort: Equatable {
    public static func == (lhs: Abort, rhs: Abort) -> Bool {
        switch (lhs, rhs) {
        case (.badRequest, .badRequest ),
             (.notFound, .notFound),
             (.serverError, .serverError):
            return true
        case (.custom(let left), .custom(let right)):
            return left.message == right.message && left.status == right.status
        default:
            return false
        }
    }
}
