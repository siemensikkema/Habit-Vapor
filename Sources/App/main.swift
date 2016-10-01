import Auth
import Habit
import Vapor
import VaporMySQL

private let authMiddleware = BearerAuthMiddleware(user: User.self)
private let drop = Droplet(
    availableMiddleware: ["auth": authMiddleware],
    preparations: [User.self],
    providers: [VaporMySQL.Provider.self])

private let jwtKey = drop.config.data(for: AppKey.jwt)!
authMiddleware.jwtKey = jwtKey

// '/auth'
private let authController = AuthController(jwtKey: jwtKey, hash: drop.hash)
drop.group("auth") {
    $0.post("update_password", handler: authController.updatePassword)
    $0.post("log_in", handler: authController.logIn)
    $0.post("register", handler: authController.register)
}

// '/'
private let credentialError = Abort.custom(status: .forbidden, message: "Invalid credentials")
private let protectMiddleware = ProtectMiddleware(error: credentialError)
drop.grouped(protectMiddleware).get("/") { _ in
    return "hello"
}

drop.run()
