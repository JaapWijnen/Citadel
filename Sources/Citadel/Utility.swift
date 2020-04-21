/// - TODO: It turned out that none of these routines were actually needed, but
///   I'm leaving them here anyway for now just in case they're interesting.
extension Swift.Result {
    
    /// Sometimes, there are cases where a `Result` is known to be in an error
    /// state, but this fact is not visible to the compiler (such as the result
    /// of doing `case .success = result`). Normally, one would use `switch`
    /// instead so the compiler had visibility that the success state was not
    /// valid. Unfortunately, sometimes this is very awkward, even to as simple
    /// an extent as introducing an otherwise entirely unnecessary code indent
    /// and readability loss in order to, for example, be able to mutate a
    /// `ByteBuffer`. Even worse, simply returning the original `Result` will
    /// often fail due to the success type not matching. Hence, this utility,
    /// which does exactly what it says: it forcibly jams the error case of the
    /// current result into an instance that has the desired type for its
    /// success case.
    ///
    /// - WARNING: If the `Result` was actually in a success state, this method
    ///   will crash, guaranteed. This is exactly as dangerous as using force-
    ///   unwrapping on an `Optional` (posibly a bit more so). The "unsafe" in
    ///   the name is there very much deliberately - consider it the equivalent
    ///   of accessing the `.unsafelyUnwrapped` property of any optional value.
    public func unsafelyRemapError<NewSuccess>() -> Result<NewSuccess, Error> {
        switch self {
        case .failure(let error):
            return .failure(error)
        case .success(_):
            // Wasn't kidding about crashing. Also, error message deliberately phrased to sound like the one
            // for unwrapping a nil optional.
            fatalError("Unexpectedly found success while remapping an error-state Result value!")
        }
    }

    /// It turns out there are a lot of times it would be nice to know whether a
    /// `Result` was in success or error state without necessarily accessing
    /// either payload _and_ without having to deal with the deeply clumsy and
    /// somewhat hateful awkwardness of `if case .foo = bar` "I can't be used as
    /// an expression, only a statement" matching.
    @inlinable public var hasSucceeded: Bool { switch self {
        case .success: return true
        case .failure: return false
    } }
    
    /// And, for good form, let's do the inverse of `hasSucceeded` as well.
    @inlinable public var hasFailed: Bool { switch self {
        case .success: return false
        case .failure: return true
    } }

}
