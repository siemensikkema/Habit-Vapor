import Vapor
import VaporMySQL

let drop = Droplet(
	preparations: [User.self],
	providers: [VaporMySQL.Provider.self])

drop.run()
