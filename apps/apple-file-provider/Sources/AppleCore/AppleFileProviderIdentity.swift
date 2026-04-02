import Foundation

public struct AppleFileProviderItemIdentifier: Sendable, Codable, Hashable, Equatable, CustomStringConvertible {
    public var kind: AppleFileProviderItemIdentifierKind
    public var payload: String

    public init(kind: AppleFileProviderItemIdentifierKind, payload: String = "") {
        self.kind = kind
        self.payload = kind == .root ? "" : payload.trimmedIdentifierPayload
    }

    public static let root = AppleFileProviderItemIdentifier(kind: .root)

    public static func file(objectID: String) -> Self {
        Self(kind: .file, payload: objectID)
    }

    public static func temporaryFile(path: String) -> Self {
        Self(kind: .temporaryFile, payload: normalizedPath(path))
    }

    public static func directory(path: String) -> Self {
        let normalized = normalizedPath(path)
        return normalized.isEmpty ? .root : Self(kind: .directory, payload: normalized)
    }

    public init?(serialized: String) {
        let trimmed = serialized.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed == "root" || trimmed == "dir:root" {
            self = .root
            return
        }

        if let payload = trimmed.stripPrefix("file:object:") {
            self = .file(objectID: payload)
            return
        }

        if let payload = trimmed.stripPrefix("file:path:") {
            guard !payload.isEmpty else {
                return nil
            }
            self = .temporaryFile(path: payload)
            return
        }

        if let payload = trimmed.stripPrefix("dir:path:") {
            self = .directory(path: payload)
            return
        }

        // Accept earlier placeholder forms too so native code can read any
        // intermediate serialized values while we settle on the Rust C-ABI IDs.
        if let payload = trimmed.stripPrefix("file:") {
            guard !payload.isEmpty else {
                return nil
            }
            self = .file(objectID: payload)
            return
        }

        if let payload = trimmed.stripPrefix("dir:") {
            self = .directory(path: payload)
            return
        }

        if let payload = trimmed.stripPrefix("temp-file:") ?? trimmed.stripPrefix("temporary_file:") {
            guard !payload.isEmpty else {
                return nil
            }
            self = .temporaryFile(path: payload)
            return
        }

        return nil
    }

    public var description: String {
        serialized
    }

    public var serialized: String {
        switch kind {
        case .root:
            return "dir:root"
        case .file:
            return "file:object:\(payload)"
        case .directory:
            return "dir:path:\(payload)"
        case .temporaryFile:
            return "file:path:\(payload)"
        }
    }

    public var directoryPath: String? {
        switch kind {
        case .root:
            return ""
        case .directory:
            return payload
        case .file, .temporaryFile:
            return nil
        }
    }

    public var fileObjectID: String? {
        kind == .file ? payload : nil
    }

    public var temporaryFilePath: String? {
        kind == .temporaryFile ? payload : nil
    }
}

public enum AppleFileProviderItemIdentifierKind: String, Sendable, Codable, CaseIterable {
    case root
    case file
    case directory
    case temporaryFile = "temporary_file"
}

private extension String {
    var trimmedIdentifierPayload: String {
        trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func stripPrefix(_ prefix: String) -> String? {
        guard hasPrefix(prefix) else {
            return nil
        }
        return String(dropFirst(prefix.count))
    }
}
