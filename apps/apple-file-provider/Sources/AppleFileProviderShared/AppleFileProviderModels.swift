import Foundation
import AppleCore

public struct AppleFileProviderItem: Sendable, Codable, Equatable {
    public var identifier: AppleFileProviderItemIdentifier
    public var path: String
    public var displayName: String
    public var kind: AppleFileProviderItemKind
    public var objectID: String?
    public var revisionHint: String?
    public var sizeBytes: Int64?
    public var modifiedAtUnix: Int64?
    public var conflictState: AppleConflictState?

    public init(
        identifier: AppleFileProviderItemIdentifier,
        path: String,
        displayName: String? = nil,
        kind: AppleFileProviderItemKind,
        objectID: String? = nil,
        revisionHint: String? = nil,
        sizeBytes: Int64? = nil,
        modifiedAtUnix: Int64? = nil,
        conflictState: AppleConflictState? = nil
    ) {
        self.identifier = identifier
        self.path = normalizedPath(path)
        self.displayName = displayName.nilIfBlank ?? self.path.lastPathComponentOrFallback
        self.kind = kind
        self.objectID = objectID.nilIfBlank
        self.revisionHint = revisionHint.nilIfBlank
        self.sizeBytes = sizeBytes
        self.modifiedAtUnix = modifiedAtUnix
        self.conflictState = conflictState
    }

    public static func file(
        path: String,
        objectID: String?,
        revisionHint: String? = nil,
        sizeBytes: Int64? = nil,
        modifiedAtUnix: Int64? = nil,
        conflictState: AppleConflictState? = nil,
        displayName: String? = nil
    ) -> Self {
        let normalized = normalizedPath(path)
        let identifier = objectID.nilIfBlank.map(AppleFileProviderItemIdentifier.file(objectID:)) ??
            AppleFileProviderItemIdentifier.temporaryFile(path: normalized)
        return Self(
            identifier: identifier,
            path: normalized,
            displayName: displayName ?? normalized.lastPathComponentOrFallback,
            kind: .file,
            objectID: objectID.nilIfBlank,
            revisionHint: revisionHint,
            sizeBytes: sizeBytes,
            modifiedAtUnix: modifiedAtUnix,
            conflictState: conflictState
        )
    }

    public static func directory(
        path: String,
        revisionHint: String? = nil,
        modifiedAtUnix: Int64? = nil,
        conflictState: AppleConflictState? = nil,
        displayName: String? = nil
    ) -> Self {
        let normalized = normalizedPath(path)
        let identifier = AppleFileProviderItemIdentifier.directory(path: normalized)
        return Self(
            identifier: identifier,
            path: normalized,
            displayName: displayName ?? normalized.lastPathComponentOrFallback,
            kind: .directory,
            objectID: nil,
            revisionHint: revisionHint,
            sizeBytes: nil,
            modifiedAtUnix: modifiedAtUnix,
            conflictState: conflictState
        )
    }

    public var isDurable: Bool {
        objectID != nil
    }
}
