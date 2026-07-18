import Foundation

public struct AppleDirectoryLoadRequest: Equatable, Sendable {
    public let generation: UInt64
    public let path: String
    public let updatesRootSnapshot: Bool
    public let updatesCurrentDirectory: Bool
    public let updatesCurrentPath: Bool

    init(
        generation: UInt64,
        path: String,
        updatesRootSnapshot: Bool,
        updatesCurrentDirectory: Bool,
        updatesCurrentPath: Bool
    ) {
        self.generation = generation
        self.path = normalizedPath(path)
        self.updatesRootSnapshot = updatesRootSnapshot
        self.updatesCurrentDirectory = updatesCurrentDirectory
        self.updatesCurrentPath = updatesCurrentDirectory && updatesCurrentPath
    }
}

public struct AppleDirectoryLoadCoordinator: Sendable {
    private var nextGeneration: UInt64 = 0
    private var latestRootSnapshotGeneration: UInt64?
    private var latestCurrentDirectoryGeneration: UInt64?
    private var latestSharedStateGeneration: UInt64?

    public init() {}

    public mutating func begin(
        path: String,
        updatesCurrentDirectory: Bool,
        updatesCurrentPath: Bool = false
    ) -> AppleDirectoryLoadRequest {
        nextGeneration &+= 1

        let normalized = normalizedPath(path)
        let updatesRootSnapshot = normalized.isEmpty
        let request = AppleDirectoryLoadRequest(
            generation: nextGeneration,
            path: normalized,
            updatesRootSnapshot: updatesRootSnapshot,
            updatesCurrentDirectory: updatesCurrentDirectory,
            updatesCurrentPath: updatesCurrentPath
        )

        if updatesRootSnapshot {
            latestRootSnapshotGeneration = request.generation
        }
        if updatesCurrentDirectory {
            latestCurrentDirectoryGeneration = request.generation
        }
        latestSharedStateGeneration = request.generation

        return request
    }

    public func acceptsRootSnapshot(_ request: AppleDirectoryLoadRequest) -> Bool {
        request.updatesRootSnapshot
            && latestRootSnapshotGeneration == request.generation
    }

    public func acceptsCurrentDirectory(_ request: AppleDirectoryLoadRequest) -> Bool {
        request.updatesCurrentDirectory
            && latestCurrentDirectoryGeneration == request.generation
    }

    public func acceptsSharedState(_ request: AppleDirectoryLoadRequest) -> Bool {
        latestSharedStateGeneration == request.generation
    }

    public func acceptsAnyResult(from request: AppleDirectoryLoadRequest) -> Bool {
        acceptsRootSnapshot(request)
            || acceptsCurrentDirectory(request)
            || acceptsSharedState(request)
    }

    public mutating func invalidate() {
        latestRootSnapshotGeneration = nil
        latestCurrentDirectoryGeneration = nil
        latestSharedStateGeneration = nil
    }
}
