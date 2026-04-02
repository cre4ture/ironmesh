import Foundation

public typealias AppleRustHandle = UnsafeMutableRawPointer

public protocol AppleManualCBridgeFFI: Sendable {
    func createHandle(
        connectionInput: String,
        serverCAPem: String?,
        clientIdentityJSON: String?
    ) throws -> AppleRustHandle

    func freeHandle(_ handle: AppleRustHandle)
    func listJSON(handle: AppleRustHandle, prefix: String?, depth: Int, snapshot: String?) throws -> String
    func metadataJSON(handle: AppleRustHandle, key: String) throws -> String
    func fetchBytes(handle: AppleRustHandle, key: String) throws -> Data
    func putBytes(handle: AppleRustHandle, key: String, data: Data) throws -> String
    func deletePath(handle: AppleRustHandle, key: String) throws
    func movePath(handle: AppleRustHandle, fromPath: String, toPath: String, overwrite: Bool) throws
}

public enum AppleManualCBridgeError: Error, Sendable, Equatable, LocalizedError {
    case notConnected
    case unsupportedIdentifier(String)
    case invalidResponse(String)

    public var errorDescription: String? {
        switch self {
        case .notConnected:
            return "The Apple Rust bridge is not connected."
        case .unsupportedIdentifier(let identifier):
            return "The Apple Rust bridge cannot resolve identifier '\(identifier)' yet."
        case .invalidResponse(let message):
            return "The Apple Rust bridge returned an invalid response: \(message)"
        }
    }
}

public final class AppleCFacadeBridge: AppleManualCBridge, @unchecked Sendable {
    private let ffi: AppleManualCBridgeFFI
    private let lock = NSLock()
    private var handle: AppleRustHandle?

    public init(ffi: AppleManualCBridgeFFI) {
        self.ffi = ffi
    }

    deinit {
        disconnectIfNeeded()
    }

    public func connect(_ configuration: AppleConnectionConfiguration) throws -> AppleBridgeSession {
        let newHandle = try ffi.createHandle(
            connectionInput: configuration.normalizedConnectionInput,
            serverCAPem: configuration.serverCAPem,
            clientIdentityJSON: configuration.clientIdentityJSON
        )

        lock.lock()
        let previousHandle = handle
        handle = newHandle
        lock.unlock()

        if let previousHandle {
            ffi.freeHandle(previousHandle)
        }

        return AppleBridgeSession(
            sessionID: UUID().uuidString,
            domainIdentifier: configuration.normalizedConnectionInput,
            rootPath: "/"
        )
    }

    public func list(path: String, depth: Int) throws -> [AppleBridgeItem] {
        try withHandle { handle in
            let responseJSON = try ffi.listJSON(
                handle: handle,
                prefix: normalizedListPrefix(path),
                depth: depth,
                snapshot: nil
            )
            let response = try decode(RustAppleListResponse.self, from: responseJSON)
            return response.entries.map { $0.appleBridgeItem }
        }
    }

    public func metadata(pathOrIdentifier: String) throws -> AppleBridgeItem? {
        let key = try lookupPath(for: pathOrIdentifier)
        return try withHandle { handle in
            let responseJSON = try ffi.metadataJSON(handle: handle, key: key)
            let response = try decode(RustAppleMetadataResponse.self, from: responseJSON)
            return response.appleBridgeItem
        }
    }

    public func download(path: String, revisionHint: String?) throws -> Data {
        _ = revisionHint
        return try withHandle { handle in
            try ffi.fetchBytes(handle: handle, key: normalizedPath(path))
        }
    }

    public func upload(path: String, data: Data, expectedRevision: String?) throws -> AppleMutationResult {
        _ = expectedRevision
        return try withHandle { handle in
            let responseJSON = try ffi.putBytes(handle: handle, key: normalizedPath(path), data: data)
            let response = try decode(RustApplePutResponse.self, from: responseJSON)
            return AppleMutationResult(
                accepted: true,
                resultingIdentifier: response.itemID,
                resultingRevision: response.versionGraph?.preferredHeadVersionID
            )
        }
    }

    public func mkdir(path: String) throws -> AppleMutationResult {
        let normalized = normalizedPath(path)
        guard !normalized.isEmpty else {
            return AppleMutationResult(accepted: true, message: "Root already exists.", resultingIdentifier: AppleFileProviderItemIdentifier.root.serialized)
        }

        return AppleMutationResult(
            accepted: false,
            message: "Directory creation is not implemented in the Apple Rust bridge yet.",
            resultingIdentifier: AppleFileProviderItemIdentifier.directory(path: normalized).serialized
        )
    }

    public func delete(path: String, expectedRevision: String?) throws -> AppleMutationResult {
        _ = expectedRevision
        return try withHandle { handle in
            let normalized = normalizedPath(path)
            try ffi.deletePath(handle: handle, key: normalized)
            return AppleMutationResult(accepted: true)
        }
    }

    public func move(from: String, to: String, expectedRevision: String?) throws -> AppleMutationResult {
        _ = expectedRevision
        return try withHandle { handle in
            let source = normalizedPath(from)
            let destination = normalizedPath(to)
            try ffi.movePath(handle: handle, fromPath: source, toPath: destination, overwrite: false)
            return AppleMutationResult(
                accepted: true,
                resultingIdentifier: inferredIdentifier(for: destination, objectID: nil).serialized
            )
        }
    }

    public func refresh(cursor: String?) throws -> AppleRefreshResult {
        AppleRefreshResult(changed: false, cursor: cursor, changedPaths: [])
    }

    private func disconnectIfNeeded() {
        lock.lock()
        let existingHandle = handle
        handle = nil
        lock.unlock()

        if let existingHandle {
            ffi.freeHandle(existingHandle)
        }
    }

    private func withHandle<T>(_ body: (AppleRustHandle) throws -> T) throws -> T {
        lock.lock()
        let existingHandle = handle
        lock.unlock()

        guard let existingHandle else {
            throw AppleManualCBridgeError.notConnected
        }

        return try body(existingHandle)
    }

    private func decode<T: Decodable>(_ type: T.Type, from json: String) throws -> T {
        let data = Data(json.utf8)
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw AppleManualCBridgeError.invalidResponse(error.localizedDescription)
        }
    }

    private func lookupPath(for pathOrIdentifier: String) throws -> String {
        let normalizedInput = pathOrIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedInput.isEmpty else {
            return ""
        }

        guard let identifier = AppleFileProviderItemIdentifier(serialized: normalizedInput) else {
            return normalizedPath(normalizedInput)
        }

        switch identifier.kind {
        case .root:
            return ""
        case .directory:
            return identifier.directoryPath ?? ""
        case .temporaryFile:
            return identifier.temporaryFilePath ?? normalizedInput
        case .file:
            throw AppleManualCBridgeError.unsupportedIdentifier(normalizedInput)
        }
    }

    private func normalizedListPrefix(_ path: String) -> String? {
        let normalized = normalizedPath(path)
        guard !normalized.isEmpty else {
            return nil
        }
        return normalized.hasSuffix("/") ? normalized : "\(normalized)/"
    }
}

private struct RustAppleListResponse: Decodable {
    var entries: [RustAppleListEntry]
}

private struct RustAppleListEntry: Decodable {
    var path: String
    var itemID: String
    var kind: AppleFileProviderItemKind
    var objectID: String?
    var preferredHeadVersionID: String?
    var version: String?
    var sizeBytes: UInt64?
    var modifiedAtUnix: UInt64?

    enum CodingKeys: String, CodingKey {
        case path
        case itemID = "item_id"
        case kind
        case objectID = "object_id"
        case preferredHeadVersionID = "preferred_head_version_id"
        case version
        case sizeBytes = "size_bytes"
        case modifiedAtUnix = "modified_at_unix"
    }

    var appleBridgeItem: AppleBridgeItem {
        AppleBridgeItem(
            path: path,
            displayName: normalizedPath(path).lastPathComponentOrFallback,
            identifier: inferredIdentifier(for: path, serializedIdentifier: itemID, objectID: objectID),
            kind: kind,
            objectID: objectID,
            revisionHint: preferredHeadVersionID ?? version,
            sizeBytes: sizeBytes.map(Int64.init),
            modifiedAtUnix: modifiedAtUnix.map(Int64.init),
            conflictState: nil
        )
    }
}

private struct RustAppleMetadataResponse: Decodable {
    var key: String
    var itemID: String
    var kind: AppleFileProviderItemKind
    var objectID: String?
    var versionGraph: RustAppleVersionGraph?

    enum CodingKeys: String, CodingKey {
        case key
        case itemID = "item_id"
        case kind
        case objectID = "object_id"
        case versionGraph = "version_graph"
    }

    var appleBridgeItem: AppleBridgeItem {
        AppleBridgeItem(
            path: key,
            displayName: normalizedPath(key).lastPathComponentOrFallback,
            identifier: inferredIdentifier(for: key, serializedIdentifier: itemID, objectID: objectID),
            kind: kind,
            objectID: objectID,
            revisionHint: versionGraph?.preferredHeadVersionID,
            sizeBytes: nil,
            modifiedAtUnix: nil,
            conflictState: nil
        )
    }
}

private struct RustApplePutResponse: Decodable {
    var itemID: String
    var objectID: String?
    var versionGraph: RustAppleVersionGraph?

    enum CodingKeys: String, CodingKey {
        case itemID = "item_id"
        case objectID = "object_id"
        case versionGraph = "version_graph"
    }
}

private struct RustAppleVersionGraph: Decodable {
    var preferredHeadVersionID: String?

    enum CodingKeys: String, CodingKey {
        case preferredHeadVersionID = "preferred_head_version_id"
    }
}

private func inferredIdentifier(
    for path: String,
    serializedIdentifier: String? = nil,
    objectID: String?
) -> AppleFileProviderItemIdentifier {
    if let serializedIdentifier, let parsed = AppleFileProviderItemIdentifier(serialized: serializedIdentifier) {
        return parsed
    }
    return inferredIdentifier(for: path, objectID: objectID)
}

private func inferredIdentifier(for path: String, objectID: String?) -> AppleFileProviderItemIdentifier {
    let normalized = normalizedPath(path)
    if let objectID = objectID?.nilIfBlank {
        return .file(objectID: objectID)
    }
    if normalized.isEmpty {
        return .root
    }
    if path.hasSuffix("/") {
        return .directory(path: normalized)
    }
    return .temporaryFile(path: normalized)
}
