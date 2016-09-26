import Fluent
import Vapor

final class User: Model {
	var exists = false
	var id: Node?
	var name: String

	init(name: String) {
		self.name = name
	}

	// NodeInitializable
	init(node: Node, in context: Context) throws {
		id = try node.extract("id")
		name = try node.extract("name")
	}
}

// NodeRepresentable
extension User {
    func makeNode(context: Context) throws -> Node {
        return try Node(node: [
            "id": id,
            "name": name
        ])
    }
}


// Preparation
extension User {
	static func prepare(_ database: Database) throws {
		try database.create("users") { users in
			users.id()
			users.string("name")
		}
	}

	static func revert(_ database: Database) throws {
		try database.delete("users")
	}
}
