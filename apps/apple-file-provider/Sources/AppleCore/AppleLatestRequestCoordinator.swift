/// Coordinates async work where only the latest request may publish or finalize UI state.
public struct AppleLatestRequestCoordinator: Sendable {
    public struct Token: Equatable, Sendable {
        fileprivate let generation: UInt64
    }

    private var generation: UInt64 = 0
    private var currentToken: Token?

    public init() {}

    public var hasCurrentRequest: Bool {
        currentToken != nil
    }

    @discardableResult
    public mutating func begin() -> Token {
        generation &+= 1
        let token = Token(generation: generation)
        currentToken = token
        return token
    }

    public func isCurrent(_ token: Token) -> Bool {
        currentToken == token
    }

    public mutating func invalidate() {
        generation &+= 1
        currentToken = nil
    }

    @discardableResult
    public mutating func complete(_ token: Token) -> Bool {
        guard isCurrent(token) else {
            return false
        }
        currentToken = nil
        return true
    }
}
