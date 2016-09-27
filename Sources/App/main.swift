import Auth
import Vapor
import VaporMySQL

let auth = BearerAuthMiddleware(user: User.self)
let drop = Droplet(
	availableMiddleware: ["auth": auth],
	preparations: [User.self],
	providers: [VaporMySQL.Provider.self])

// after initializing the droplet, use its config for the auth middleware
auth.config = drop.config

// '/auth'
let authController = AuthController(drop: drop, path: "auth")

// '/'
let credentialError = Abort.custom(status: .forbidden, message: "Invalid credentials")
let protect = ProtectMiddleware(error: credentialError)
drop.grouped(protect).get("/") { _ in
	return "hello"
}

drop.run()
