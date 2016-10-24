import HTTP

struct TestResponder: Responder {
    func respond(to request: Request) throws -> Response {
        return Response()
    }
}
