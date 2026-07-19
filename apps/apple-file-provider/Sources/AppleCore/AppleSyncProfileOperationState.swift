public struct AppleSyncProfileOperationState: Equatable, Sendable {
    public private(set) var isMutationInProgress = false

    public init() {}

    public mutating func beginMutation() -> Bool {
        guard !isMutationInProgress else {
            return false
        }
        isMutationInProgress = true
        return true
    }

    public mutating func endMutation() {
        isMutationInProgress = false
    }
}
