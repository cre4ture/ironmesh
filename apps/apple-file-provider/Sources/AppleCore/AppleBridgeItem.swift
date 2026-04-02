import Foundation

public enum AppleFileProviderItemKind: String, Sendable, Codable, CaseIterable {
    case file
    case directory
}

public struct AppleBridgeItemReference: Sendable, Codable, Hashable, Equatable {
    public var path: String
    public var identifier: AppleFileProviderItemIdentifier?

    public init(path: String, identifier: AppleFileProviderItemIdentifier? = nil) {
        self.path = normalizedPath(path)
        self.identifier = identifier
    }
}
