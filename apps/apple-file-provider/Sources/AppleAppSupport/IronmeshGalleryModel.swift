import AppleCore
import Combine
import Foundation

struct IronmeshGalleryLoadContext: Equatable, Sendable {
    let configuration: AppleConnectionConfiguration
    let query: AppleGalleryQuery
}

@MainActor
final class IronmeshGalleryModel: ObservableObject {
    @Published private(set) var entries: [AppleStoreIndexEntry] = []
    @Published private(set) var totalCount = 0
    @Published private(set) var isLoading = false
    @Published private(set) var errorMessage: String?

    let imageRepository: IronmeshGalleryImageRepository

    private let remoteSession: IronmeshGalleryRemoteSession
    private var activeContext: IronmeshGalleryLoadContext?
    private var activeGeneration: UInt64?
    private var pagination = AppleGalleryPagination()
    private var requestGate = AppleGalleryRequestGate()
    private var pageTask: Task<Void, Never>?

    init(
        remoteSession: IronmeshGalleryRemoteSession = IronmeshGalleryRemoteSession(),
        imageRepository: IronmeshGalleryImageRepository = IronmeshGalleryImageRepository()
    ) {
        self.remoteSession = remoteSession
        self.imageRepository = imageRepository
    }

    var canLoadMore: Bool {
        pagination.hasMore && entries.count < totalCount
    }

    func reload(
        mode: AppleGalleryMode,
        sort: AppleGallerySort,
        currentPath: String,
        configuration: AppleConnectionConfiguration?,
        force: Bool = false
    ) {
        guard let configuration else {
            resetWithError("Configure a connection before loading photos.")
            return
        }

        let context = IronmeshGalleryLoadContext(
            configuration: configuration,
            query: AppleGalleryQuery(mode: mode, currentPath: currentPath, sort: sort)
        )
        guard force || context != activeContext else {
            return
        }

        pageTask?.cancel()
        let generation = requestGate.begin()
        activeContext = context
        activeGeneration = generation
        pagination = AppleGalleryPagination()
        entries = []
        totalCount = 0
        errorMessage = nil
        imageRepository.prepare(for: configuration)
        loadPage(context: context, generation: generation, offset: 0)
    }

    func refresh() {
        guard let activeContext else {
            return
        }
        reload(
            mode: activeContext.query.mode,
            sort: activeContext.query.sort,
            currentPath: activeContext.query.currentPath,
            configuration: activeContext.configuration,
            force: true
        )
    }

    func loadNextPage() {
        guard
            !isLoading,
            pagination.hasMore,
            let activeContext,
            let activeGeneration,
            requestGate.accepts(activeGeneration)
        else {
            return
        }
        loadPage(
            context: activeContext,
            generation: activeGeneration,
            offset: pagination.nextOffset
        )
    }

    func retry() {
        if entries.isEmpty {
            refresh()
        } else {
            loadNextPage()
        }
    }

    func invalidate() {
        pageTask?.cancel()
        pageTask = nil
        requestGate.invalidate()
        activeGeneration = nil
        isLoading = false
    }

    func suspend() {
        invalidate()
        activeContext = nil
    }

    private func loadPage(
        context: IronmeshGalleryLoadContext,
        generation: UInt64,
        offset: Int
    ) {
        let request = context.query.request(offset: offset)
        let remoteSession = remoteSession
        isLoading = true
        errorMessage = nil

        pageTask = Task { [weak self] in
            do {
                let response = try await Task.detached(priority: .userInitiated) {
                    try remoteSession.storeIndex(request, configuration: context.configuration)
                }.value

                guard
                    let self,
                    self.requestGate.accepts(generation),
                    self.activeContext == context
                else {
                    return
                }

                let imageEntries = response.entries.filter { $0.entryType == .key }
                let existingPaths = Set(self.entries.map(\.path))
                self.entries.append(contentsOf: imageEntries.filter { !existingPaths.contains($0.path) })
                self.pagination.record(response)
                self.totalCount = max(response.totalEntryCount, self.entries.count)
                self.isLoading = false
                self.errorMessage = nil
            } catch {
                guard
                    let self,
                    self.requestGate.accepts(generation),
                    self.activeContext == context
                else {
                    return
                }
                self.isLoading = false
                self.errorMessage = error.localizedDescription
            }
        }
    }

    private func resetWithError(_ message: String) {
        invalidate()
        activeContext = nil
        entries = []
        totalCount = 0
        pagination = AppleGalleryPagination()
        errorMessage = message
    }
}

final class IronmeshGalleryImageRepository: @unchecked Sendable {
    private let thumbnailCache = NSCache<NSString, NSData>()
    private let fullImageCache = NSCache<NSString, NSData>()
    private let thumbnailSessions: [IronmeshGalleryRemoteSession]
    private let fullImageSession: IronmeshGalleryRemoteSession
    private let cacheContextLock = NSLock()
    private var cacheContextGate = AppleGalleryCacheContextGate()

    init(
        thumbnailSessions: [IronmeshGalleryRemoteSession]? = nil,
        fullImageSession: IronmeshGalleryRemoteSession = IronmeshGalleryRemoteSession()
    ) {
        let defaultSessions = (0..<4).map { _ in IronmeshGalleryRemoteSession() }
        self.thumbnailSessions = thumbnailSessions?.isEmpty == false
            ? thumbnailSessions ?? defaultSessions
            : defaultSessions
        self.fullImageSession = fullImageSession
        thumbnailCache.countLimit = 160
        thumbnailCache.totalCostLimit = 48 * 1_024 * 1_024
        fullImageCache.countLimit = 4
        fullImageCache.totalCostLimit = 96 * 1_024 * 1_024
    }

    func prepare(for configuration: AppleConnectionConfiguration) {
        cacheContextLock.lock()
        defer { cacheContextLock.unlock() }
        let preparation = cacheContextGate.prepare(for: configuration)
        guard preparation.contextChanged else {
            return
        }
        thumbnailCache.removeAllObjects()
        fullImageCache.removeAllObjects()
    }

    func thumbnailData(
        for entry: AppleStoreIndexEntry,
        configuration: AppleConnectionConfiguration
    ) async throws -> Data {
        let cacheKey = AppleGalleryCacheIdentity.thumbnailKey(for: entry)
        let lookup = try cacheLookup(
            cache: thumbnailCache,
            key: cacheKey,
            configuration: configuration
        )
        if let data = lookup.data {
            return data
        }

        let relativePath = AppleGalleryThumbnailPath.relativePath(for: entry)
        let thumbnailSession = thumbnailSession(for: entry.path)
        let data = try await Task.detached(priority: .utility) {
            try thumbnailSession.fetchRelativeBytes(
                path: relativePath,
                configuration: configuration
            )
        }.value

        try storeCacheResult(
            data,
            cache: thumbnailCache,
            key: cacheKey,
            generation: lookup.generation,
            configuration: configuration
        )
        return data
    }

    func fullImageData(
        for entry: AppleStoreIndexEntry,
        configuration: AppleConnectionConfiguration
    ) async throws -> Data {
        let cacheKey = AppleGalleryCacheIdentity.fullImageKey(for: entry)
        let lookup = try cacheLookup(
            cache: fullImageCache,
            key: cacheKey,
            configuration: configuration
        )
        if let data = lookup.data {
            return data
        }

        let fullImageSession = fullImageSession
        let data = try await Task.detached(priority: .userInitiated) {
            try fullImageSession.download(path: entry.path, configuration: configuration)
        }.value

        try storeCacheResult(
            data,
            cache: fullImageCache,
            key: cacheKey,
            generation: lookup.generation,
            configuration: configuration
        )
        return data
    }

    private func cacheLookup(
        cache: NSCache<NSString, NSData>,
        key: String,
        configuration: AppleConnectionConfiguration
    ) throws -> (generation: UInt64, data: Data?) {
        cacheContextLock.lock()
        defer { cacheContextLock.unlock() }
        guard let generation = cacheContextGate.generation(for: configuration) else {
            throw IronmeshGalleryImageRepositoryError.staleConnectionContext
        }
        let data = cache.object(forKey: key as NSString).map(Data.init(referencing:))
        return (generation, data)
    }

    private func storeCacheResult(
        _ data: Data,
        cache: NSCache<NSString, NSData>,
        key: String,
        generation: UInt64,
        configuration: AppleConnectionConfiguration
    ) throws {
        cacheContextLock.lock()
        defer { cacheContextLock.unlock() }
        guard cacheContextGate.accepts(generation: generation, configuration: configuration) else {
            throw IronmeshGalleryImageRepositoryError.staleConnectionContext
        }
        cache.setObject(data as NSData, forKey: key as NSString, cost: data.count)
    }

    private func thumbnailSession(for path: String) -> IronmeshGalleryRemoteSession {
        var hash: UInt64 = 5381
        for byte in path.utf8 {
            hash = ((hash << 5) &+ hash) &+ UInt64(byte)
        }
        return thumbnailSessions[Int(hash % UInt64(thumbnailSessions.count))]
    }
}

private enum IronmeshGalleryImageRepositoryError: LocalizedError {
    case staleConnectionContext

    var errorDescription: String? {
        "The gallery connection changed before the image finished loading."
    }
}

final class IronmeshGalleryRemoteSession: @unchecked Sendable {
    private let bridge: AppleCFacadeBridge
    private let lock = NSLock()
    private var configuration: AppleConnectionConfiguration?

    init(ffi: AppleManualCBridgeFFI = IronmeshRustFFIAdapter(connectionName: "ios gallery")) {
        bridge = AppleCFacadeBridge(ffi: ffi)
    }

    func storeIndex(
        _ request: AppleStoreIndexRequest,
        configuration: AppleConnectionConfiguration
    ) throws -> AppleStoreIndexResponse {
        try withBridge(configuration: configuration) { bridge in
            try bridge.storeIndex(request)
        }
    }

    func fetchRelativeBytes(
        path: String,
        configuration: AppleConnectionConfiguration
    ) throws -> Data {
        try withBridge(configuration: configuration) { bridge in
            try bridge.fetchRelativeBytes(path: path)
        }
    }

    func download(
        path: String,
        configuration: AppleConnectionConfiguration
    ) throws -> Data {
        try withBridge(configuration: configuration) { bridge in
            try bridge.download(path: path, revisionHint: nil)
        }
    }

    private func withBridge<T>(
        configuration nextConfiguration: AppleConnectionConfiguration,
        operation: (AppleCFacadeBridge) throws -> T
    ) throws -> T {
        lock.lock()
        defer { lock.unlock() }

        if configuration != nextConfiguration {
            _ = try bridge.connect(nextConfiguration)
            configuration = nextConfiguration
        }
        return try operation(bridge)
    }
}
