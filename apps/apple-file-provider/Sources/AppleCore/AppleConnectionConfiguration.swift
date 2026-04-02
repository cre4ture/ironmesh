import Foundation

public struct AppleConnectionConfiguration: Sendable, Codable, Equatable {
    public var connectionInput: String
    public var serverCAPem: String?
    public var clientIdentityJSON: String?

    public init(
        connectionInput: String,
        serverCAPem: String? = nil,
        clientIdentityJSON: String? = nil
    ) {
        self.connectionInput = connectionInput
        self.serverCAPem = serverCAPem?.nilIfBlank
        self.clientIdentityJSON = clientIdentityJSON?.nilIfBlank
    }

    public var normalizedConnectionInput: String {
        normalizedConnectionInputString(connectionInput)
    }
}

public struct AppleBridgeSession: Sendable, Codable, Equatable {
    public var sessionID: String
    public var domainIdentifier: String?
    public var rootPath: String?

    public init(sessionID: String, domainIdentifier: String? = nil, rootPath: String? = nil) {
        self.sessionID = sessionID
        self.domainIdentifier = domainIdentifier?.nilIfBlank
        self.rootPath = rootPath?.nilIfBlank
    }
}

public enum AppleBridgeOperation: String, Sendable, Codable, CaseIterable {
    case connect
    case list
    case metadata
    case download
    case upload
    case mkdir
    case delete
    case move
    case refresh
}

public protocol AppleRustBridge: Sendable {
    func connect(_ configuration: AppleConnectionConfiguration) throws -> AppleBridgeSession
    func list(path: String, depth: Int) throws -> [AppleBridgeItem]
    func metadata(pathOrIdentifier: String) throws -> AppleBridgeItem?
    func download(path: String, revisionHint: String?) throws -> Data
    func upload(path: String, data: Data, expectedRevision: String?) throws -> AppleMutationResult
    func mkdir(path: String) throws -> AppleMutationResult
    func delete(path: String, expectedRevision: String?) throws -> AppleMutationResult
    func move(from: String, to: String, expectedRevision: String?) throws -> AppleMutationResult
    func refresh(cursor: String?) throws -> AppleRefreshResult
}

public struct AppleMutationResult: Sendable, Codable, Equatable {
    public var accepted: Bool
    public var message: String?
    public var resultingIdentifier: String?
    public var resultingRevision: String?

    public init(
        accepted: Bool,
        message: String? = nil,
        resultingIdentifier: String? = nil,
        resultingRevision: String? = nil
    ) {
        self.accepted = accepted
        self.message = message?.nilIfBlank
        self.resultingIdentifier = resultingIdentifier?.nilIfBlank
        self.resultingRevision = resultingRevision?.nilIfBlank
    }
}

public struct AppleRefreshResult: Sendable, Codable, Equatable {
    public var changed: Bool
    public var cursor: String?
    public var changedPaths: [String]

    public init(changed: Bool, cursor: String? = nil, changedPaths: [String] = []) {
        self.changed = changed
        self.cursor = cursor?.nilIfBlank
        self.changedPaths = changedPaths.map(normalizedPath)
    }
}

public struct AppleBridgeItem: Sendable, Codable, Equatable {
    public var path: String
    public var displayName: String
    public var identifier: AppleFileProviderItemIdentifier
    public var kind: AppleFileProviderItemKind
    public var objectID: String?
    public var revisionHint: String?
    public var sizeBytes: Int64?
    public var modifiedAtUnix: Int64?
    public var conflictState: AppleConflictState?

    public init(
        path: String,
        displayName: String,
        identifier: AppleFileProviderItemIdentifier,
        kind: AppleFileProviderItemKind,
        objectID: String? = nil,
        revisionHint: String? = nil,
        sizeBytes: Int64? = nil,
        modifiedAtUnix: Int64? = nil,
        conflictState: AppleConflictState? = nil
    ) {
        self.path = normalizedPath(path)
        self.displayName = displayName.nilIfBlank ?? self.path.lastPathComponentOrFallback
        self.identifier = identifier
        self.kind = kind
        self.objectID = objectID?.nilIfBlank
        self.revisionHint = revisionHint?.nilIfBlank
        self.sizeBytes = sizeBytes
        self.modifiedAtUnix = modifiedAtUnix
        self.conflictState = conflictState
    }
}

public struct AppleConflictState: Sendable, Codable, Equatable {
    public var status: AppleConflictStatus
    public var reason: AppleConflictReasonCode?
    public var preferredRevision: String?
    public var alternateRevisions: [String]
    public var conflictCopyPath: String?

    public init(
        status: AppleConflictStatus,
        reason: AppleConflictReasonCode? = nil,
        preferredRevision: String? = nil,
        alternateRevisions: [String] = [],
        conflictCopyPath: String? = nil
    ) {
        self.status = status
        self.reason = reason
        self.preferredRevision = preferredRevision?.nilIfBlank
        self.alternateRevisions = alternateRevisions.map { $0.trimmedNonBlank }.compactMap { $0 }
        self.conflictCopyPath = conflictCopyPath?.nilIfBlank.map(normalizedPath)
    }
}

public enum AppleConflictStatus: String, Sendable, Codable, CaseIterable {
    case clean
    case pendingUpload = "pending_upload"
    case conflicted
    case readOnly = "read_only"
    case placeholder
}

public enum AppleConflictReasonCode: String, Sendable, Codable, CaseIterable {
    case modifyModify = "modify_modify"
    case modifyDelete = "modify_delete"
    case renameCollision = "rename_collision"
    case unknown
}

public extension String {
    var trimmedNonBlank: String? {
        nilIfBlank
    }

    var lastPathComponentOrFallback: String {
        let component = normalizedPath(self).split(separator: "/").last.map(String.init)
        return component?.nilIfBlank ?? "item"
    }
}

func normalizedConnectionInputString(_ value: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
        return trimmed
    }
    if trimmed.hasPrefix("{") || trimmed.contains("://") {
        return trimmed
    }
    let withScheme = "http://\(trimmed)"
    return withScheme.hasSuffix("/") ? withScheme : "\(withScheme)/"
}
