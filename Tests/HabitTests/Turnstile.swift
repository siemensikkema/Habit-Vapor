@testable import Habit
import Auth
import Cache
import Turnstile

extension Turnstile {
    static var testTurnstile: Turnstile {
        let cache = MemoryCache()
        let realm = AuthenticatorRealm(User.self)
        let sessionManager = CacheSessionManager(cache: cache, realm: realm)
        return Turnstile(sessionManager: sessionManager, realm: realm)
    }
}
