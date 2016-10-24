import Foundation
import Vapor

protocol ConfigKey: RawRepresentable {
    static var context: String { get }
}

enum AppKey: String, ConfigKey {
    static let context = "app"

    case jwt = "JWTKey"
}

extension Config {
    func string<T: ConfigKey>(for key: T) -> String? where T.RawValue == String {
        return self[T.context, key.rawValue]?.string
    }

    func data<T: ConfigKey>(for key: T) -> Data? where T.RawValue == String {
        return string(for: key)?.data(using: .utf8)
    }
}
