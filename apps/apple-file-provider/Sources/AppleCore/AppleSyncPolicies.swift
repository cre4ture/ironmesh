import Foundation

public struct AppleSyncEnvironmentSnapshot: Equatable, Sendable {
    public var isConnected: Bool
    public var isExpensive: Bool
    public var isConstrained: Bool
    public var isLowPowerModeEnabled: Bool

    public init(
        isConnected: Bool,
        isExpensive: Bool = false,
        isConstrained: Bool = false,
        isLowPowerModeEnabled: Bool = false
    ) {
        self.isConnected = isConnected
        self.isExpensive = isExpensive
        self.isConstrained = isConstrained
        self.isLowPowerModeEnabled = isLowPowerModeEnabled
    }
}

public enum AppleSyncConstraintDecision: Equatable, Sendable {
    case allowed
    case blocked(String)

    public var isAllowed: Bool {
        if case .allowed = self {
            return true
        }
        return false
    }
}

public enum AppleSyncConstraintEvaluator {
    public static func evaluate(
        profile: AppleSyncProfile,
        environment: AppleSyncEnvironmentSnapshot
    ) -> AppleSyncConstraintDecision {
        guard profile.lifecycle == .active else {
            return .blocked("This sync profile is paused.")
        }
        guard environment.isConnected else {
            return .blocked("No network connection is currently available.")
        }
        if environment.isExpensive, !profile.networkPolicy.allowsExpensiveNetwork {
            return .blocked("This profile does not allow expensive or cellular network paths.")
        }
        if environment.isConstrained, !profile.networkPolicy.allowsConstrainedNetwork {
            return .blocked("This profile is deferred while Low Data Mode constrains the network.")
        }
        if environment.isLowPowerModeEnabled, profile.powerPolicy.defersInLowPowerMode {
            return .blocked("This profile is deferred while Low Power Mode is enabled.")
        }
        return .allowed
    }
}

public enum AppleSyncRecoverySignalPolicy {
    public static func shouldSignal(
        profile: AppleSyncProfile,
        previous: AppleSyncEnvironmentSnapshot,
        current: AppleSyncEnvironmentSnapshot
    ) -> Bool {
        !AppleSyncConstraintEvaluator.evaluate(
            profile: profile,
            environment: previous
        ).isAllowed
            && AppleSyncConstraintEvaluator.evaluate(
                profile: profile,
                environment: current
            ).isAllowed
    }
}

public enum AppleDeletionCapabilityPolicy {
    public static func allowsDeletion(for kind: AppleFileProviderItemIdentifierKind) -> Bool {
        switch kind {
        case .file, .temporaryFile:
            true
        case .root, .directory:
            false
        }
    }
}

public struct AppleProfilePathMapper: Equatable, Sendable {
    public let remotePrefix: String

    public init(remotePrefix: String) {
        self.remotePrefix = normalizedPath(remotePrefix)
    }

    public func remotePath(forLocalPath localPath: String) -> String {
        let local = normalizedPath(localPath)
        guard !remotePrefix.isEmpty else {
            return local
        }
        guard !local.isEmpty else {
            return remotePrefix
        }
        return "\(remotePrefix)/\(local)"
    }

    public func localPath(forRemotePath remotePath: String) throws -> String {
        let remote = normalizedPath(remotePath)
        guard !remotePrefix.isEmpty else {
            return remote
        }
        if remote == remotePrefix {
            return ""
        }
        let prefix = "\(remotePrefix)/"
        guard remote.hasPrefix(prefix) else {
            throw AppleProfilePathError.outsideProfile(remote)
        }
        return String(remote.dropFirst(prefix.count))
    }

    public func localItem(from remoteItem: AppleBridgeItem) throws -> AppleBridgeItem {
        let localPath = try localPath(forRemotePath: remoteItem.path)
        let identifier: AppleFileProviderItemIdentifier = switch remoteItem.identifier.kind {
        case .root:
            .root
        case .directory:
            .directory(path: localPath)
        case .temporaryFile:
            .temporaryFile(path: localPath)
        case .file:
            remoteItem.identifier
        }
        return AppleBridgeItem(
            path: localPath,
            displayName: remoteItem.displayName,
            identifier: identifier,
            kind: remoteItem.kind,
            objectID: remoteItem.objectID,
            revisionHint: remoteItem.revisionHint,
            sizeBytes: remoteItem.sizeBytes,
            modifiedAtUnix: remoteItem.modifiedAtUnix,
            conflictState: remoteItem.conflictState
        )
    }
}

public enum AppleProfilePathError: LocalizedError, Equatable {
    case outsideProfile(String)

    public var errorDescription: String? {
        switch self {
        case .outsideProfile(let path):
            return "Remote path '\(path)' is outside this sync profile."
        }
    }
}

public enum AppleConflictCopyNaming {
    public static func path(
        originalPath: String,
        expectedRevision: String,
        currentRevision: String
    ) -> String {
        let normalized = normalizedPath(originalPath)
        let parent: String
        let filename: String
        if let slash = normalized.lastIndex(of: "/") {
            parent = String(normalized[..<slash])
            filename = String(normalized[normalized.index(after: slash)...])
        } else {
            parent = ""
            filename = normalized.lastPathComponentOrFallback
        }

        let url = URL(fileURLWithPath: filename)
        let pathExtension = url.pathExtension
        let stem = url.deletingPathExtension().lastPathComponent
        let suffix = stableFingerprint("\(normalized)\n\(expectedRevision)\n\(currentRevision)")
        let extensionSuffix = pathExtension.isEmpty ? "" : ".\(pathExtension)"
        let copyName = "\(stem) (IronMesh conflict \(suffix))\(extensionSuffix)"
        return parent.isEmpty ? copyName : "\(parent)/\(copyName)"
    }

    private static func stableFingerprint(_ value: String) -> String {
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001b3
        }
        return String(format: "%012llx", hash & 0x0000_FFFF_FFFF_FFFF)
    }
}
