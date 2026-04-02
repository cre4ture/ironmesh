import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

struct IronmeshBundleConfiguration {
    let domainIdentifier: String
    let domainDisplayName: String
    let connectionInput: String

    init(bundle: Bundle = .main) {
        let info = bundle.infoDictionary ?? [:]
        domainIdentifier = (info["IronmeshDomainIdentifier"] as? String)?.nilIfBlank ?? "dev.ironmesh.default"
        domainDisplayName = (info["IronmeshDomainDisplayName"] as? String)?.nilIfBlank ?? "IronMesh"
        connectionInput = (info["IronmeshConnectionInput"] as? String)?.nilIfBlank ?? "127.0.0.1:18080"
    }

    var connectionConfiguration: AppleConnectionConfiguration {
        AppleConnectionConfiguration(connectionInput: connectionInput)
    }

    var domain: NSFileProviderDomain {
        NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: domainIdentifier), displayName: domainDisplayName)
    }
}

final class IronmeshIdentifierPathCache: @unchecked Sendable {
    private let fileURL: URL
    private let lock = NSLock()
    private var mappings: [String: String]

    init(domainIdentifier: String) {
        let supportRoot = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let cacheDirectory = supportRoot.appendingPathComponent("IronMeshApple", isDirectory: true)
        try? FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
        fileURL = cacheDirectory.appendingPathComponent("\(domainIdentifier)-identifier-path-cache.json")
        mappings = Self.loadMappings(from: fileURL)
    }

    func record(items: [AppleBridgeItem]) {
        lock.lock()
        defer { lock.unlock() }

        for item in items {
            record(item)
        }

        persist()
    }

    func path(for identifier: AppleFileProviderItemIdentifier) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return mappings[identifier.serialized]
    }

    private func record(_ item: AppleBridgeItem) {
        let path = normalizedPath(item.path)
        guard !path.isEmpty else {
            return
        }
        mappings[item.identifier.serialized] = path
    }

    private func persist() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(mappings) else {
            return
        }
        try? data.write(to: fileURL, options: .atomic)
    }

    private static func loadMappings(from url: URL) -> [String: String] {
        guard let data = try? Data(contentsOf: url) else {
            return [:]
        }
        return (try? JSONDecoder().decode([String: String].self, from: data)) ?? [:]
    }
}

final class IronmeshFileProviderService: @unchecked Sendable {
    let configuration: IronmeshBundleConfiguration

    private let bridge: AppleCFacadeBridge
    private let cache: IronmeshIdentifierPathCache
    private let lock = NSLock()
    private var connected = false

    init(
        configuration: IronmeshBundleConfiguration = IronmeshBundleConfiguration(),
        ffi: AppleManualCBridgeFFI = IronmeshRustFFIAdapter()
    ) {
        self.configuration = configuration
        bridge = AppleCFacadeBridge(ffi: ffi)
        cache = IronmeshIdentifierPathCache(domainIdentifier: configuration.domainIdentifier)
    }

    func rootItem() -> AppleBridgeItem {
        AppleBridgeItem(
            path: "",
            displayName: configuration.domainDisplayName,
            identifier: .root,
            kind: .directory
        )
    }

    func list(path: String) throws -> [AppleBridgeItem] {
        try connectIfNeeded()
        let items = try bridge.list(path: path, depth: 1)
        cache.record(items: items)
        return items
    }

    func item(for identifier: NSFileProviderItemIdentifier) throws -> AppleBridgeItem {
        if identifier == .rootContainer {
            return rootItem()
        }

        try connectIfNeeded()
        let appleIdentifier = try appleIdentifier(from: identifier)
        let lookupPath = try pathForLookup(identifier: appleIdentifier)
        let item = try bridge.metadata(pathOrIdentifier: lookupPath + (appleIdentifier.kind == .directory && !lookupPath.hasSuffix("/") ? "/" : ""))
            ?? { throw fileProviderError(.noSuchItem) }()
        cache.record(items: [item])
        return item
    }

    func fetchContents(for identifier: NSFileProviderItemIdentifier) throws -> (URL, AppleBridgeItem) {
        let item = try item(for: identifier)
        let appleIdentifier = try appleIdentifier(from: identifier)
        let lookupPath = try pathForLookup(identifier: appleIdentifier)
        let data = try bridge.download(path: lookupPath, revisionHint: item.revisionHint)

        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("IronMeshDownloads", isDirectory: true)
        try FileManager.default.createDirectory(at: temporaryDirectory, withIntermediateDirectories: true)
        let fileURL = temporaryDirectory.appendingPathComponent(UUID().uuidString + "-" + item.displayName)
        try data.write(to: fileURL, options: .atomic)
        return (fileURL, item)
    }

    func registerDomain(completionHandler: @escaping (Error?) -> Void) {
        let completion = UncheckedBox(completionHandler)
        NSFileProviderManager.add(configuration.domain) { error in
            completion.value(error)
        }
    }

    private func connectIfNeeded() throws {
        lock.lock()
        let alreadyConnected = connected
        lock.unlock()

        if alreadyConnected {
            return
        }

        _ = try bridge.connect(configuration.connectionConfiguration)

        lock.lock()
        connected = true
        lock.unlock()
    }

    private func appleIdentifier(from identifier: NSFileProviderItemIdentifier) throws -> AppleFileProviderItemIdentifier {
        if identifier == .rootContainer {
            return .root
        }

        guard let parsed = AppleFileProviderItemIdentifier(serialized: identifier.rawValue) else {
            throw fileProviderError(.noSuchItem)
        }
        return parsed
    }

    private func pathForLookup(identifier: AppleFileProviderItemIdentifier) throws -> String {
        switch identifier.kind {
        case .root:
            return ""
        case .directory:
            return identifier.directoryPath ?? ""
        case .temporaryFile:
            return identifier.temporaryFilePath ?? ""
        case .file:
            guard let path = cache.path(for: identifier) else {
                throw fileProviderError(.noSuchItem)
            }
            return path
        }
    }
}

final class IronmeshFileProviderItem: NSObject, NSFileProviderItem {
    private let bridgeItem: AppleBridgeItem
    private let domainDisplayName: String

    init(bridgeItem: AppleBridgeItem, domainDisplayName: String) {
        self.bridgeItem = bridgeItem
        self.domainDisplayName = domainDisplayName
    }

    var itemIdentifier: NSFileProviderItemIdentifier {
        switch bridgeItem.identifier.kind {
        case .root:
            return .rootContainer
        default:
            return NSFileProviderItemIdentifier(rawValue: bridgeItem.identifier.serialized)
        }
    }

    var parentItemIdentifier: NSFileProviderItemIdentifier {
        if bridgeItem.identifier.kind == .root {
            return .rootContainer
        }

        let normalized = normalizedPath(bridgeItem.path)
        guard let slashIndex = normalized.lastIndex(of: "/") else {
            return .rootContainer
        }

        let parentPath = String(normalized[..<slashIndex])
        if parentPath.isEmpty {
            return .rootContainer
        }
        return NSFileProviderItemIdentifier(rawValue: AppleFileProviderItemIdentifier.directory(path: parentPath).serialized)
    }

    var filename: String {
        if bridgeItem.identifier.kind == .root {
            return domainDisplayName
        }
        return bridgeItem.displayName.nilIfBlank ?? normalizedPath(bridgeItem.path).lastPathComponentOrFallback
    }

    var contentType: UTType {
        if bridgeItem.kind == .directory {
            return .folder
        }

        let pathExtension = URL(fileURLWithPath: bridgeItem.path).pathExtension
        if let type = UTType(filenameExtension: pathExtension), !pathExtension.isEmpty {
            return type
        }
        return .data
    }

    var capabilities: NSFileProviderItemCapabilities {
        [.allowsReading]
    }

    var documentSize: NSNumber? {
        guard let sizeBytes = bridgeItem.sizeBytes, bridgeItem.kind == .file else {
            return nil
        }
        return NSNumber(value: sizeBytes)
    }

    var childItemCount: NSNumber? {
        bridgeItem.kind == .directory ? NSNumber(value: 0) : nil
    }

    var contentModificationDate: Date? {
        bridgeItem.modifiedAtUnix.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    var creationDate: Date? {
        contentModificationDate
    }

    var itemVersion: NSFileProviderItemVersion {
        let metadata = truncatedVersionData(bridgeItem.identifier.serialized)
        let content = truncatedVersionData(bridgeItem.revisionHint ?? bridgeItem.identifier.serialized)
        return NSFileProviderItemVersion(contentVersion: content, metadataVersion: metadata)
    }

    var isUploaded: Bool {
        true
    }

    var isUploading: Bool {
        false
    }

    var isMostRecentVersionDownloaded: Bool {
        true
    }
}

final class IronmeshFileProviderEnumerator: NSObject, NSFileProviderEnumerator, @unchecked Sendable {
    private let containerIdentifier: NSFileProviderItemIdentifier
    private let service: IronmeshFileProviderService

    init(containerIdentifier: NSFileProviderItemIdentifier, service: IronmeshFileProviderService) {
        self.containerIdentifier = containerIdentifier
        self.service = service
    }

    func invalidate() {
    }

    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        _ = page
        let observerBox = UncheckedBox(observer)
        DispatchQueue.global(qos: .userInitiated).async {
            let observer = observerBox.value
            do {
                if self.containerIdentifier == .workingSet {
                    observer.finishEnumerating(upTo: nil)
                    return
                }

                let containerItem = try self.service.item(for: self.containerIdentifier)
                let path = containerItem.identifier.kind == .root ? "" : normalizedPath(containerItem.path)
                let items = try self.service.list(path: path)
                let fileProviderItems = items.map {
                    IronmeshFileProviderItem(
                        bridgeItem: $0,
                        domainDisplayName: self.service.configuration.domainDisplayName
                    )
                }
                observer.didEnumerate(fileProviderItems)
                observer.finishEnumerating(upTo: nil)
            } catch {
                observer.finishEnumeratingWithError(asNSError(error))
            }
        }
    }

    func enumerateChanges(for observer: NSFileProviderChangeObserver, from syncAnchor: NSFileProviderSyncAnchor) {
        _ = syncAnchor
        observer.finishEnumeratingChanges(
            upTo: NSFileProviderSyncAnchor(rawValue: Data()),
            moreComing: false
        )
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        completionHandler(NSFileProviderSyncAnchor(rawValue: Data()))
    }
}

open class IronmeshFileProviderExtensionHost: NSObject, NSFileProviderReplicatedExtension, @unchecked Sendable {
    public let domain: NSFileProviderDomain
    let service: IronmeshFileProviderService

    public required init(domain: NSFileProviderDomain) {
        self.domain = domain
        service = IronmeshFileProviderService(
            configuration: IronmeshBundleConfiguration(bundle: Bundle(for: Self.self))
        )
        super.init()
    }

    public func invalidate() {
    }

    public func item(
        for identifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, (any Error)?) -> Void
    ) -> Progress {
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let item = try self.service.item(for: identifier)
                progress.completedUnitCount = 1
                completion.value(
                    IronmeshFileProviderItem(
                        bridgeItem: item,
                        domainDisplayName: self.service.configuration.domainDisplayName
                    ),
                    nil
                )
            } catch {
                completion.value(nil, asNSError(error))
            }
        }
        return progress
    }

    public func fetchContents(
        for itemIdentifier: NSFileProviderItemIdentifier,
        version requestedVersion: NSFileProviderItemVersion?,
        request: NSFileProviderRequest,
        completionHandler: @escaping (URL?, NSFileProviderItem?, (any Error)?) -> Void
    ) -> Progress {
        _ = requestedVersion
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let (fileURL, item) = try self.service.fetchContents(for: itemIdentifier)
                progress.completedUnitCount = 1
                completion.value(
                    fileURL,
                    IronmeshFileProviderItem(
                        bridgeItem: item,
                        domainDisplayName: self.service.configuration.domainDisplayName
                    ),
                    nil
                )
            } catch {
                completion.value(nil, nil, asNSError(error))
            }
        }
        return progress
    }

    public func enumerator(
        for containerItemIdentifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest
    ) throws -> any NSFileProviderEnumerator {
        _ = request
        return IronmeshFileProviderEnumerator(containerIdentifier: containerItemIdentifier, service: service)
    }

    public func createItem(
        basedOn itemTemplate: NSFileProviderItem,
        fields: NSFileProviderItemFields,
        contents url: URL?,
        options: NSFileProviderCreateItemOptions,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, (any Error)?) -> Void
    ) -> Progress {
        _ = itemTemplate
        _ = fields
        _ = url
        _ = options
        _ = request
        let progress = Progress(totalUnitCount: 1)
        completionHandler(nil, [], false, readOnlyMutationError())
        return progress
    }

    public func modifyItem(
        _ item: NSFileProviderItem,
        baseVersion: NSFileProviderItemVersion,
        changedFields: NSFileProviderItemFields,
        contents url: URL?,
        options: NSFileProviderModifyItemOptions,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, (any Error)?) -> Void
    ) -> Progress {
        _ = item
        _ = baseVersion
        _ = changedFields
        _ = url
        _ = options
        _ = request
        let progress = Progress(totalUnitCount: 1)
        completionHandler(nil, [], false, readOnlyMutationError())
        return progress
    }

    public func deleteItem(
        identifier itemIdentifier: NSFileProviderItemIdentifier,
        baseVersion: NSFileProviderItemVersion,
        options: NSFileProviderDeleteItemOptions,
        request: NSFileProviderRequest,
        completionHandler: @escaping ((any Error)?) -> Void
    ) -> Progress {
        _ = itemIdentifier
        _ = baseVersion
        _ = options
        _ = request
        let progress = Progress(totalUnitCount: 1)
        completionHandler(readOnlyMutationError())
        return progress
    }
}

private func truncatedVersionData(_ value: String) -> Data {
    let data = Data(value.utf8)
    if data.count <= 128 {
        return data
    }
    return data.prefix(128)
}

private func asNSError(_ error: Error) -> NSError {
    if let nsError = error as NSError? {
        return nsError
    }
    return NSError(
        domain: NSCocoaErrorDomain,
        code: NSXPCConnectionReplyInvalid,
        userInfo: [NSUnderlyingErrorKey: error]
    )
}

private func fileProviderError(_ code: NSFileProviderError.Code) -> NSError {
    NSError(domain: NSFileProviderErrorDomain, code: code.rawValue)
}

private func readOnlyMutationError() -> NSError {
    NSError(domain: NSCocoaErrorDomain, code: NSFileWriteNoPermissionError)
}

private final class UncheckedBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}
