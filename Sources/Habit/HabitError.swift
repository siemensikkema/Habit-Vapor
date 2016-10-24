enum HabitError: Error {
    case couldNotLogIn
    case couldNotVerifyClaims
    case couldNotVerifySignature
    case missingBearerHeader
}
