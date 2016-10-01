func catchError(from expression: () throws -> Void) -> Error? {
    do {
        try expression()
        return nil
    } catch {
        return error
    }
}
