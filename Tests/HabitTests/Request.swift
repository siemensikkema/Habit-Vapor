import HTTP
import JSON
import Node
import Turnstile

extension Request {

    convenience init(body: [String: String]) throws {
        try self.init(body: JSON(Node(dictionary: body)))
    }

    convenience init(
        body: BodyRepresentable = "",
        headers: [HeaderKey: String] = ["Content-Type": "application/json; charset=utf-8"]) throws {
        try self.init(
            method: .post,
            uri: "http://www.example.com",
            headers: headers,
            body: body.makeBody())

        let subject = Subject(turnstile: .testTurnstile)
        storage["subject"] = subject
    }
}

extension Node {

    init(dictionary: [String: String]) {
        var converted: [String: Node] = [:]

        dictionary.forEach {
            converted[$0.key] = .string($0.value)
        }

        self = .object(converted)
    }
}
