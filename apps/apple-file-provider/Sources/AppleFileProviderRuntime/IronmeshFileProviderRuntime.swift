import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

struct IronmeshBundleConfiguration {
    let domainIdentifier: String
    let domainDisplayName: String
    let connectionInput: String
    let appGroupIdentifier: String?

    init(
        domainIdentifier: String,
        domainDisplayName: String = "IronMesh",
        connectionInput: String = "127.0.0.1:18080",
        appGroupIdentifier: String? = nil
    ) {
        self.domainIdentifier = domainIdentifier.nilIfBlank ?? "dev.ironmesh.default"
        self.domainDisplayName = domainDisplayName.nilIfBlank ?? "IronMesh"
        self.connectionInput = connectionInput.nilIfBlank ?? "127.0.0.1:18080"
        self.appGroupIdentifier = appGroupIdentifier.nilIfBlank
    }

    init(bundle: Bundle = .main) {
        let info = bundle.infoDictionary ?? [:]
        domainIdentifier = (info["IronmeshDomainIdentifier"] as? String)?.nilIfBlank ?? "dev.ironmesh.default"
        domainDisplayName = (info["IronmeshDomainDisplayName"] as? String)?.nilIfBlank ?? "IronMesh"
        connectionInput = (info["IronmeshConnectionInput"] as? String)?.nilIfBlank ?? "127.0.0.1:18080"
        appGroupIdentifier = (info["IronmeshAppGroupIdentifier"] as? String)?.nilIfBlank
    }

    var defaultConnectionConfiguration: AppleConnectionConfiguration {
        AppleConnectionConfiguration(connectionInput: connectionInput)
    }

    var domain: NSFileProviderDomain {
        NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: domainIdentifier), displayName: domainDisplayName)
    }

    func makeSettingsStore() -> AppleConnectionSettingsStore {
        AppleConnectionSettingsStore(suiteName: appGroupIdentifier)
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

    func record(item: AppleBridgeItem) {
        lock.lock()
        defer { lock.unlock() }
        record(item)
        persist()
    }

    func path(for identifier: AppleFileProviderItemIdentifier) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return mappings[identifier.serialized]
    }

    func movePathPrefix(from sourcePath: String, to destinationPath: String) {
        let normalizedSource = normalizedPath(sourcePath)
        let normalizedDestination = normalizedPath(destinationPath)
        guard !normalizedSource.isEmpty, normalizedSource != normalizedDestination else {
            return
        }

        lock.lock()
        defer { lock.unlock() }

        var changed = false
        for (identifier, path) in mappings {
            guard let rewrittenPath = rewrittenPath(path, from: normalizedSource, to: normalizedDestination) else {
                continue
            }
            guard rewrittenPath != path else {
                continue
            }
            mappings[identifier] = rewrittenPath
            changed = true
        }

        if changed {
            persist()
        }
    }

    func removeSubtree(at path: String) {
        let normalized = normalizedPath(path)
        guard !normalized.isEmpty else {
            return
        }

        let descendantPrefix = "\(normalized)/"
        lock.lock()
        defer { lock.unlock() }

        let originalCount = mappings.count
        mappings = mappings.filter { _, value in
            value != normalized && !value.hasPrefix(descendantPrefix)
        }

        if mappings.count != originalCount {
            persist()
        }
    }

    private func record(_ item: AppleBridgeItem) {
        let path = normalizedPath(item.path)
        guard !path.isEmpty else {
            return
        }
        mappings[item.identifier.serialized] = path
    }

    private func rewrittenPath(_ path: String, from sourcePath: String, to destinationPath: String) -> String? {
        guard path == sourcePath || path.hasPrefix("\(sourcePath)/") else {
            return nil
        }

        let suffix = String(path.dropFirst(sourcePath.count))
        return normalizedPath(destinationPath + suffix)
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
    private let ffi: AppleManualCBridgeFFI
    private let cache: IronmeshIdentifierPathCache
    private let settingsStore: AppleConnectionSettingsStore
    private let lock = NSLock()
    private var connected = false
    private var connectedConfiguration: AppleConnectionConfiguration?

    init(
        configuration: IronmeshBundleConfiguration = IronmeshBundleConfiguration(),
        ffi: AppleManualCBridgeFFI = IronmeshRustFFIAdapter(),
        settingsStore: AppleConnectionSettingsStore? = nil
    ) {
        self.configuration = configuration
        self.ffi = ffi
        bridge = AppleCFacadeBridge(ffi: ffi)
        cache = IronmeshIdentifierPathCache(domainIdentifier: configuration.domainIdentifier)
        self.settingsStore = settingsStore ?? configuration.makeSettingsStore()
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

    func createItem(
        parentIdentifier: NSFileProviderItemIdentifier,
        filename: String,
        contentType: UTType,
        contents url: URL?
    ) throws -> AppleBridgeItem {
        let parentItem = try item(for: parentIdentifier)
        guard parentItem.kind == .directory else {
            throw fileProviderError(.noSuchItem)
        }

        let destinationPath = try childPath(parentPath: parentItem.path, filename: filename)
        if contentType.conforms(to: .folder) {
            let result = try bridge.mkdir(path: destinationPath)
            guard result.accepted else {
                throw unsupportedFeatureError(
                    result.message ?? "Directory creation is not implemented in the Apple File Provider bridge yet."
                )
            }
            return try resolvedItem(
                after: result,
                at: destinationPath,
                kind: .directory
            )
        }

        let result = try bridge.upload(
            path: destinationPath,
            data: try uploadData(from: url, allowMissingContents: true),
            expectedRevision: nil
        )
        return try resolvedItem(
            after: result,
            at: destinationPath,
            kind: .file
        )
    }

    func modifyItem(
        identifier: NSFileProviderItemIdentifier,
        filename: String,
        parentIdentifier: NSFileProviderItemIdentifier,
        contentType: UTType,
        changedFields: NSFileProviderItemFields,
        contents url: URL?
    ) throws -> AppleBridgeItem {
        let currentItem = try item(for: identifier)
        guard currentItem.identifier.kind != .root else {
            throw unsupportedFeatureError("Modifying the provider root is not supported.")
        }

        var workingPath = currentItem.path
        let wantsMove = changedFields.contains(.filename) || changedFields.contains(.parentItemIdentifier)
        if wantsMove {
            if currentItem.kind == .directory {
                throw unsupportedFeatureError("Renaming or moving directories is not supported by the Apple bridge yet.")
            }

            let destinationPath = try mutationDestinationPath(
                currentItem: currentItem,
                filename: filename,
                parentIdentifier: parentIdentifier,
                changedFields: changedFields
            )
            if destinationPath != currentItem.path {
                _ = try bridge.move(from: currentItem.path, to: destinationPath, expectedRevision: currentItem.revisionHint)
                cache.movePathPrefix(from: currentItem.path, to: destinationPath)
                workingPath = destinationPath
            }
        }

        if changedFields.contains(.contents) {
            guard currentItem.kind == .file, !contentType.conforms(to: .folder) else {
                throw unsupportedFeatureError("Directory content updates are not supported.")
            }

            let result = try bridge.upload(
                path: workingPath,
                data: try uploadData(from: url, allowMissingContents: false),
                expectedRevision: currentItem.revisionHint
            )
            return try resolvedItem(
                after: result,
                at: workingPath,
                kind: .file
            )
        }

        if workingPath != currentItem.path {
            return try resolvedItem(
                after: AppleMutationResult(accepted: true),
                at: workingPath,
                kind: currentItem.kind
            )
        }

        return currentItem
    }

    func deleteItem(
        identifier: NSFileProviderItemIdentifier,
        options: NSFileProviderDeleteItemOptions
    ) throws {
        do {
            let item = try item(for: identifier)
            guard item.identifier.kind != .root else {
                throw unsupportedFeatureError("Deleting the provider root is not supported.")
            }

            if item.kind == .directory {
                let children = try list(path: item.path)
                if !children.isEmpty && !options.contains(.recursive) {
                    throw fileProviderError(.directoryNotEmpty)
                }

                _ = try bridge.delete(path: "\(item.path)/", expectedRevision: item.revisionHint)
                cache.removeSubtree(at: item.path)
                return
            }

            _ = try bridge.delete(path: item.path, expectedRevision: item.revisionHint)
            cache.removeSubtree(at: item.path)
        } catch let error as NSError
            where error.domain == NSFileProviderErrorDomain
            && error.code == NSFileProviderError.Code.noSuchItem.rawValue {
            return
        }
    }

    func registerDomain(completionHandler: @escaping (Error?) -> Void) {
        let completion = UncheckedBox(completionHandler)
        NSFileProviderManager.add(configuration.domain) { error in
            completion.value(error)
        }
    }

    func currentConnectionConfiguration() -> AppleConnectionConfiguration {
        let stored = settingsStore.load()
        return stored?.effectiveConfiguration(fallback: configuration.defaultConnectionConfiguration)
            ?? configuration.defaultConnectionConfiguration
    }

    func storedConnectionState() -> AppleStoredConnectionState {
        settingsStore.load() ?? AppleStoredConnectionState(
            connectionInput: configuration.defaultConnectionConfiguration.connectionInput
        )
    }

    func saveConnectionState(_ state: AppleStoredConnectionState, reconnect: Bool = true) throws {
        try settingsStore.save(state)
        if reconnect {
            resetConnection()
        }
    }

    func clearStoredConnectionState() {
        settingsStore.clear()
        resetConnection()
    }

    func startWebUi() throws -> URL {
        let connectionConfiguration = currentConnectionConfiguration()
        let urlString = try ffi.startWebUi(
            connectionInput: connectionConfiguration.normalizedConnectionInput,
            serverCAPem: connectionConfiguration.serverCAPem,
            clientIdentityJSON: connectionConfiguration.clientIdentityJSON
        )
        guard let url = URL(string: urlString) else {
            throw AppleManualCBridgeError.invalidResponse("invalid Web UI URL '\(urlString)'")
        }
        return url
    }

    private func connectIfNeeded() throws {
        let configuration = currentConnectionConfiguration()
        lock.lock()
        let alreadyConnected = connected
        let currentConfiguration = connectedConfiguration
        lock.unlock()

        if alreadyConnected, currentConfiguration == configuration {
            return
        }

        _ = try bridge.connect(configuration)

        lock.lock()
        connected = true
        connectedConfiguration = configuration
        lock.unlock()
    }

    private func resetConnection() {
        lock.lock()
        connected = false
        connectedConfiguration = nil
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

    private func childPath(parentPath: String, filename: String) throws -> String {
        let normalizedParent = normalizedPath(parentPath)
        let leafName = try validatedLeafName(filename)
        guard !leafName.contains("/") else {
            throw mutationUsageError("The requested filename is invalid.")
        }
        return normalizedParent.isEmpty ? leafName : "\(normalizedParent)/\(leafName)"
    }

    private func mutationDestinationPath(
        currentItem: AppleBridgeItem,
        filename: String,
        parentIdentifier: NSFileProviderItemIdentifier,
        changedFields: NSFileProviderItemFields
    ) throws -> String {
        let destinationParentPath: String
        if changedFields.contains(.parentItemIdentifier) {
            let parentItem = try item(for: parentIdentifier)
            guard parentItem.kind == .directory else {
                throw fileProviderError(.noSuchItem)
            }
            destinationParentPath = parentItem.path
        } else {
            destinationParentPath = currentItem.parentPath
        }

        let destinationFilename = changedFields.contains(.filename)
            ? filename
            : currentItem.displayName
        return try childPath(parentPath: destinationParentPath, filename: destinationFilename)
    }

    private func resolvedItem(
        after result: AppleMutationResult,
        at path: String,
        kind: AppleFileProviderItemKind
    ) throws -> AppleBridgeItem {
        guard result.accepted else {
            throw unsupportedFeatureError(result.message ?? "The Apple bridge rejected the mutation.")
        }

        let metadataPath = kind == .directory ? "\(normalizedPath(path))/" : normalizedPath(path)
        if let item = try? bridge.metadata(pathOrIdentifier: metadataPath) {
            cache.record(item: item)
            return item
        }

        let item = AppleBridgeItem(
            path: path,
            displayName: normalizedPath(path).lastPathComponentOrFallback,
            identifier: resolvedIdentifier(
                serializedIdentifier: result.resultingIdentifier,
                path: path,
                kind: kind
            ),
            kind: kind,
            revisionHint: result.resultingRevision
        )
        cache.record(item: item)
        return item
    }

    private func resolvedIdentifier(
        serializedIdentifier: String?,
        path: String,
        kind: AppleFileProviderItemKind
    ) -> AppleFileProviderItemIdentifier {
        if let serializedIdentifier,
           let identifier = AppleFileProviderItemIdentifier(serialized: serializedIdentifier) {
            return identifier
        }

        switch kind {
        case .directory:
            return .directory(path: path)
        case .file:
            return .temporaryFile(path: path)
        }
    }

    private func uploadData(from url: URL?, allowMissingContents: Bool) throws -> Data {
        guard let url else {
            if allowMissingContents {
                return Data()
            }
            throw mutationUsageError("The Apple File Provider did not receive file contents for this update.")
        }
        return try Data(contentsOf: url)
    }

    private func validatedLeafName(_ value: String) throws -> String {
        guard let trimmed = value.nilIfBlank else {
            throw mutationUsageError("The Apple File Provider requires a non-empty filename.")
        }
        return trimmed
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
        switch bridgeItem.identifier.kind {
        case .root:
            return [.allowsReading, .allowsWriting]
        case .directory:
            return [.allowsReading, .allowsWriting, .allowsDeleting]
        case .file, .temporaryFile:
            return [.allowsReading, .allowsWriting, .allowsRenaming, .allowsReparenting, .allowsDeleting]
        }
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
        _ = fields
        _ = options
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let item = try self.service.createItem(
                    parentIdentifier: itemTemplate.parentItemIdentifier,
                    filename: itemTemplate.filename,
                    contentType: itemTemplate.contentType ?? .data,
                    contents: url
                )
                progress.completedUnitCount = 1
                completion.value(
                    self.providerItem(item),
                    [],
                    false,
                    nil
                )
            } catch {
                completion.value(nil, [], false, asNSError(error))
            }
        }
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
        _ = baseVersion
        _ = options
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        let supportedFields: NSFileProviderItemFields = [
            .contents,
            .filename,
            .parentItemIdentifier
        ]
        let actionableFields = changedFields.intersection(supportedFields)
        let unsupportedFields = changedFields.subtracting(supportedFields)

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let updatedItem: AppleBridgeItem
                if actionableFields.isEmpty {
                    updatedItem = try self.service.item(for: item.itemIdentifier)
                } else {
                    updatedItem = try self.service.modifyItem(
                        identifier: item.itemIdentifier,
                        filename: item.filename,
                        parentIdentifier: item.parentItemIdentifier,
                        contentType: item.contentType ?? .data,
                        changedFields: actionableFields,
                        contents: url
                    )
                }

                progress.completedUnitCount = 1
                completion.value(
                    self.providerItem(updatedItem),
                    unsupportedFields,
                    false,
                    nil
                )
            } catch {
                completion.value(nil, [], false, asNSError(error))
            }
        }
        return progress
    }

    public func deleteItem(
        identifier itemIdentifier: NSFileProviderItemIdentifier,
        baseVersion: NSFileProviderItemVersion,
        options: NSFileProviderDeleteItemOptions,
        request: NSFileProviderRequest,
        completionHandler: @escaping ((any Error)?) -> Void
    ) -> Progress {
        _ = baseVersion
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.service.deleteItem(identifier: itemIdentifier, options: options)
                progress.completedUnitCount = 1
                completion.value(nil)
            } catch {
                completion.value(asNSError(error))
            }
        }
        return progress
    }

    private func providerItem(_ bridgeItem: AppleBridgeItem) -> IronmeshFileProviderItem {
        IronmeshFileProviderItem(
            bridgeItem: bridgeItem,
            domainDisplayName: service.configuration.domainDisplayName
        )
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

private func unsupportedFeatureError(_ message: String) -> NSError {
    NSError(
        domain: NSCocoaErrorDomain,
        code: NSFeatureUnsupportedError,
        userInfo: [NSLocalizedDescriptionKey: message]
    )
}

private func mutationUsageError(_ message: String) -> NSError {
    NSError(
        domain: NSCocoaErrorDomain,
        code: NSXPCConnectionReplyInvalid,
        userInfo: [NSLocalizedDescriptionKey: message]
    )
}

private final class UncheckedBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

private extension AppleBridgeItem {
    var parentPath: String {
        let normalized = normalizedPath(path)
        guard let slashIndex = normalized.lastIndex(of: "/") else {
            return ""
        }
        return String(normalized[..<slashIndex])
    }
}
