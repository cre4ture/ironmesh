import Foundation

public enum AppleStoreIndexView: String, Codable, Equatable, Sendable {
    case raw
    case tree
}

public enum AppleStoreIndexSortOrder: String, Codable, Equatable, Sendable {
    case pathAscending = "path_asc"
    case capturedDescending = "captured_desc"
}

public enum AppleStoreIndexMediaFilter: String, Codable, Equatable, Sendable {
    case all
    case image
    case video
}

public enum AppleStoreIndexEntryType: Codable, Equatable, Sendable {
    case key
    case prefix
    case unknown(String)

    public init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer().decode(String.self)
        switch value {
        case "key":
            self = .key
        case "prefix":
            self = .prefix
        default:
            self = .unknown(value)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .key:
            try container.encode("key")
        case .prefix:
            try container.encode("prefix")
        case .unknown(let value):
            try container.encode(value)
        }
    }
}

public enum AppleStoreIndexMediaStatus: Codable, Equatable, Sendable {
    case ready
    case pending
    case incomplete
    case unsupported
    case unknown(String)

    public init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer().decode(String.self)
        switch value {
        case "ready":
            self = .ready
        case "pending":
            self = .pending
        case "incomplete":
            self = .incomplete
        case "unsupported":
            self = .unsupported
        default:
            self = .unknown(value)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .ready:
            try container.encode("ready")
        case .pending:
            try container.encode("pending")
        case .incomplete:
            try container.encode("incomplete")
        case .unsupported:
            try container.encode("unsupported")
        case .unknown(let value):
            try container.encode(value)
        }
    }
}

public struct AppleStoreIndexRequestOptions: Equatable, Sendable {
    public var view: AppleStoreIndexView?
    public var offset: Int?
    public var limit: Int?
    public var sort: AppleStoreIndexSortOrder?
    public var mediaFilter: AppleStoreIndexMediaFilter?

    public init(
        view: AppleStoreIndexView? = nil,
        offset: Int? = nil,
        limit: Int? = nil,
        sort: AppleStoreIndexSortOrder? = nil,
        mediaFilter: AppleStoreIndexMediaFilter? = nil
    ) {
        self.view = view
        self.offset = offset.map { max(0, $0) }
        self.limit = limit.map { max(1, $0) }
        self.sort = sort
        self.mediaFilter = mediaFilter
    }
}

public struct AppleStoreIndexRequest: Equatable, Sendable {
    public var prefix: String?
    public var depth: Int
    public var snapshot: String?
    public var options: AppleStoreIndexRequestOptions

    public init(
        prefix: String? = nil,
        depth: Int,
        snapshot: String? = nil,
        options: AppleStoreIndexRequestOptions = AppleStoreIndexRequestOptions()
    ) {
        let normalizedPrefix = normalizedPath(prefix ?? "")
        self.prefix = normalizedPrefix.isEmpty ? nil : normalizedPrefix
        self.depth = max(1, depth)
        self.snapshot = snapshot?.nilIfBlank
        self.options = options
    }
}

public struct AppleStoreIndexResponse: Codable, Equatable, Sendable {
    public var prefix: String
    public var depth: Int
    public var entryCount: Int
    public var totalEntryCount: Int
    public var offset: Int
    public var limit: Int?
    public var hasMore: Bool
    public var nextCursor: String?
    public var mediaSummary: AppleStoreIndexMediaSummary
    public var entries: [AppleStoreIndexEntry]

    enum CodingKeys: String, CodingKey {
        case prefix
        case depth
        case entryCount = "entry_count"
        case totalEntryCount = "total_entry_count"
        case offset
        case limit
        case hasMore = "has_more"
        case nextCursor = "next_cursor"
        case mediaSummary = "media_summary"
        case entries
    }
}

public struct AppleStoreIndexMediaSummary: Codable, Equatable, Sendable {
    public var readyCount: Int
    public var pendingCount: Int
    public var incompleteCount: Int
    public var imageCount: Int
    public var videoCount: Int
    public var geotaggedCount: Int

    enum CodingKeys: String, CodingKey {
        case readyCount = "ready_count"
        case pendingCount = "pending_count"
        case incompleteCount = "incomplete_count"
        case imageCount = "image_count"
        case videoCount = "video_count"
        case geotaggedCount = "geotagged_count"
    }
}

public struct AppleStoreIndexEntry: Codable, Equatable, Sendable, Identifiable {
    public var path: String
    public var entryType: AppleStoreIndexEntryType
    public var version: String?
    public var contentHash: String?
    public var sizeBytes: UInt64?
    public var modifiedAtUnix: UInt64?
    public var contentFingerprint: String?
    public var media: AppleStoreIndexMedia?

    public var id: String { path }

    enum CodingKeys: String, CodingKey {
        case path
        case entryType = "entry_type"
        case version
        case contentHash = "content_hash"
        case sizeBytes = "size_bytes"
        case modifiedAtUnix = "modified_at_unix"
        case contentFingerprint = "content_fingerprint"
        case media
    }
}

public struct AppleStoreIndexMedia: Codable, Equatable, Sendable {
    public var status: AppleStoreIndexMediaStatus
    public var contentFingerprint: String
    public var mediaType: String?
    public var mimeType: String?
    public var width: UInt32?
    public var height: UInt32?
    public var orientation: UInt16?
    public var takenAtUnix: UInt64?
    public var gps: AppleStoreIndexGPS?
    public var thumbnail: AppleStoreIndexThumbnail?
    public var error: String?

    enum CodingKeys: String, CodingKey {
        case status
        case contentFingerprint = "content_fingerprint"
        case mediaType = "media_type"
        case mimeType = "mime_type"
        case width
        case height
        case orientation
        case takenAtUnix = "taken_at_unix"
        case gps
        case thumbnail
        case error
    }
}

public struct AppleStoreIndexGPS: Codable, Equatable, Sendable {
    public var latitude: Double
    public var longitude: Double
}

public struct AppleStoreIndexThumbnail: Codable, Equatable, Sendable {
    public var url: String
    public var profile: String
    public var width: UInt32
    public var height: UInt32
    public var format: String
    public var sizeBytes: UInt64

    enum CodingKeys: String, CodingKey {
        case url
        case profile
        case width
        case height
        case format
        case sizeBytes = "size_bytes"
    }
}

public enum AppleGalleryMode: String, CaseIterable, Equatable, Sendable {
    case allImages
    case currentFolder
}

public enum AppleGallerySort: String, CaseIterable, Equatable, Sendable {
    case newest
    case path

    public var storeIndexOrder: AppleStoreIndexSortOrder {
        switch self {
        case .newest:
            return .capturedDescending
        case .path:
            return .pathAscending
        }
    }
}

public struct AppleGalleryQuery: Equatable, Sendable {
    public static let defaultPageSize = 32
    public static let flattenedDepth = 64

    public var mode: AppleGalleryMode
    public var currentPath: String
    public var sort: AppleGallerySort
    public var pageSize: Int

    public init(
        mode: AppleGalleryMode,
        currentPath: String,
        sort: AppleGallerySort,
        pageSize: Int = defaultPageSize
    ) {
        self.mode = mode
        self.currentPath = normalizedPath(currentPath)
        self.sort = sort
        self.pageSize = max(1, pageSize)
    }

    public func request(offset: Int) -> AppleStoreIndexRequest {
        AppleStoreIndexRequest(
            prefix: mode == .currentFolder ? currentPath : nil,
            depth: mode == .allImages ? Self.flattenedDepth : 1,
            options: AppleStoreIndexRequestOptions(
                view: .tree,
                offset: offset,
                limit: pageSize,
                sort: sort.storeIndexOrder,
                mediaFilter: .image
            )
        )
    }
}

public struct AppleGalleryPagination: Equatable, Sendable {
    public private(set) var nextOffset = 0
    public private(set) var totalCount = 0
    public private(set) var hasMore = true

    public init() {}

    public mutating func record(_ response: AppleStoreIndexResponse) {
        let consumed = max(response.entryCount, response.entries.count)
        nextOffset = response.offset + consumed
        totalCount = max(response.totalEntryCount, nextOffset)
        hasMore = response.hasMore && consumed > 0
    }
}

public struct AppleGalleryRequestGate: Equatable, Sendable {
    private var generation: UInt64 = 0

    public init() {}

    public mutating func begin() -> UInt64 {
        generation &+= 1
        return generation
    }

    public func accepts(_ candidate: UInt64) -> Bool {
        candidate == generation
    }

    public mutating func invalidate() {
        generation &+= 1
    }
}

public struct AppleGalleryCacheContextPreparation: Equatable, Sendable {
    public let generation: UInt64
    public let contextChanged: Bool
}

public struct AppleGalleryCacheContextGate: Equatable, Sendable {
    private var configuration: AppleConnectionConfiguration?
    private var generation: UInt64 = 0

    public init() {}

    public mutating func prepare(
        for nextConfiguration: AppleConnectionConfiguration
    ) -> AppleGalleryCacheContextPreparation {
        let contextChanged = configuration != nextConfiguration
        if contextChanged {
            configuration = nextConfiguration
            generation &+= 1
        }
        return AppleGalleryCacheContextPreparation(
            generation: generation,
            contextChanged: contextChanged
        )
    }

    public func accepts(
        generation candidate: UInt64,
        configuration candidateConfiguration: AppleConnectionConfiguration
    ) -> Bool {
        generation == candidate && configuration == candidateConfiguration
    }

    public func generation(
        for candidateConfiguration: AppleConnectionConfiguration
    ) -> UInt64? {
        configuration == candidateConfiguration ? generation : nil
    }
}

public enum AppleGalleryCacheIdentity {
    public static func thumbnailKey(for entry: AppleStoreIndexEntry) -> String {
        [
            entry.path,
            entry.contentFingerprint ?? entry.media?.contentFingerprint ?? "",
            entry.media?.thumbnail?.url ?? "",
        ].joined(separator: "\n")
    }

    public static func fullImageKey(for entry: AppleStoreIndexEntry) -> String {
        let revisionIdentity = entry.version
            ?? entry.contentHash
            ?? entry.contentFingerprint
            ?? entry.media?.contentFingerprint
            ?? fallbackObjectIdentity(for: entry)
        return [entry.path, revisionIdentity].joined(separator: "\n")
    }

    private static func fallbackObjectIdentity(for entry: AppleStoreIndexEntry) -> String {
        let modifiedAt = entry.modifiedAtUnix.map(String.init) ?? ""
        let size = entry.sizeBytes.map(String.init) ?? ""
        return "modified=\(modifiedAt);size=\(size)"
    }
}

public enum AppleGalleryThumbnailPath {
    public static func relativePath(for entry: AppleStoreIndexEntry) -> String {
        if let advertised = safeAdvertisedPath(entry.media?.thumbnail?.url) {
            return advertised
        }
        return fallbackRelativePath(forKey: entry.path)
    }

    public static func fallbackRelativePath(forKey key: String) -> String {
        let normalized = normalizedPath(key)
        let unreserved = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        let encoded = normalized.addingPercentEncoding(withAllowedCharacters: unreserved) ?? ""
        return "/media/thumbnail?key=\(encoded)"
    }

    private static func safeAdvertisedPath(_ value: String?) -> String? {
        guard let value = value?.nilIfBlank else {
            return nil
        }
        if value.hasPrefix("/"), !value.hasPrefix("//") {
            return value
        }
        if value.hasPrefix("media/") || value.hasPrefix("api/") {
            return "/\(value)"
        }
        return nil
    }
}
