import Auth
import Habit
import Vapor
import VaporMySQL

private let drop = Droplet()
private let jwtKey = try drop.config.data(for: AppKey.jwt)!.makeBytes()
private let jwtAuthentication = JWTAuthentication(jwtKey: jwtKey, user: User.self)

try drop.addProvider(VaporMySQL.Provider.self)

drop.middleware.append(jwtAuthentication)
drop.preparations.append(User.self)

// '/auth'
private let authController = AuthController(jwtKey: jwtKey, hash: drop.hash)
drop.group("auth") {
    $0.post("update_password", handler: authController.updatePassword)
    $0.post("log_in", handler: authController.logIn)
    $0.post("register", handler: authController.register)
}

// '/api'
private let credentialError = Abort.custom(status: .forbidden, message: "Invalid credentials")
private let protect = ProtectMiddleware(error: credentialError)

drop.grouped(protect).group("api") {
    let userController = UserController()
    $0.get("me", handler: userController.me)
}

drop.run()
