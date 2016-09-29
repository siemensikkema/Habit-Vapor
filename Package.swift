import PackageDescription

let package = Package(
    name: "Habit-Vapor",
    targets: [
        Target(name: "App", dependencies: ["Habit"]),
        ],
    dependencies: [
        .Package(url: "https://github.com/vapor/vapor.git", majorVersion: 1),
        .Package(url: "https://github.com/vapor/mysql-provider.git", majorVersion: 1),
        .Package(url: "https://github.com/siemensikkema/JSONWebToken.swift.git", majorVersion: 2),
        .Package(url: "https://github.com/siemensikkema/Punctual.swift.git", majorVersion: 2),
        ],
    exclude: [
        "Config",
        "Database",
        "Localization",
        "Public",
        "Resources",
        "Tests"
        ]
)
