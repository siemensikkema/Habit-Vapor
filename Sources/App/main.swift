import Auth
import Habit
import Vapor
import VaporMySQL

private let jwtAuthentication = JWTAuthentication(user: User.self)
private let drop = Droplet(
    availableMiddleware: ["auth": jwtAuthentication],
    preparations: [User.self],
    providers: [VaporMySQL.Provider.self])

private let jwtKey = drop.config.data(for: AppKey.jwt)!
jwtAuthentication.jwtKey = jwtKey

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
