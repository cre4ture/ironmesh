import Foundation

public struct AppleRemoteSnapshotItem: Codable, Equatable, Sendable {
    public var identifier: String
    public var path: String
    public var kind: AppleFileProviderItemKind
    public var revision: String

    public init(item: AppleBridgeItem) {
        identifier = item.identifier.serialized
        path = normalizedPath(item.path)
        kind = item.kind
        revision = item.revisionHint ?? "\(item.sizeBytes ?? -1):\(item.modifiedAtUnix ?? -1)"
    }
}

public struct AppleRemoteChangeBatch: Equatable, Sendable {
    public var generation: UInt64
    public var updatedIdentifiers: [String]
    public var deletedIdentifiers: [String]

    public init(
        generation: UInt64,
        updatedIdentifiers: [String] = [],
        deletedIdentifiers: [String] = []
    ) {
        self.generation = generation
        self.updatedIdentifiers = updatedIdentifiers.sorted()
        self.deletedIdentifiers = deletedIdentifiers.sorted()
    }
}

public enum AppleRemoteChangeJournalError: LocalizedError, Equatable {
    case expiredAnchor(UInt64)

    public var errorDescription: String? {
        switch self {
        case .expiredAnchor(let generation):
            return "File Provider sync anchor \(generation) has expired."
        }
    }
}

public struct AppleRemoteChangeJournal: Codable, Equatable, Sendable {
    public private(set) var generation: UInt64
    public private(set) var items: [String: AppleRemoteSnapshotItem]
    private var events: [Event]
    private let retainedEventCount: Int

    public init(retainedEventCount: Int = 64) {
        generation = 0
        items = [:]
        events = []
        self.retainedEventCount = max(retainedEventCount, 1)
    }

    @discardableResult
    public mutating func reconcile(_ currentItems: [AppleBridgeItem]) -> AppleRemoteChangeBatch {
        let current = currentItems.reduce(into: [String: AppleRemoteSnapshotItem]()) {
            result, bridgeItem in
            let snapshot = AppleRemoteSnapshotItem(item: bridgeItem)
            guard let existing = result[snapshot.identifier] else {
                result[snapshot.identifier] = snapshot
                return
            }
            // A malformed/legacy remote index may expose one durable identifier at multiple
            // paths. File Provider cannot represent both. Pick one deterministically and let a
            // later repaired index produce a normal change instead of trapping the extension.
            if Self.snapshotOrder(snapshot, existing) {
                result[snapshot.identifier] = snapshot
            }
        }
        let updated = current.compactMap { identifier, item in
            items[identifier] == item ? nil : identifier
        }.sorted()
        let deleted = items.keys.filter { current[$0] == nil }.sorted()

        guard !updated.isEmpty || !deleted.isEmpty else {
            return AppleRemoteChangeBatch(generation: generation)
        }

        generation &+= 1
        items = current
        events.append(Event(generation: generation, updated: updated, deleted: deleted))
        if events.count > retainedEventCount {
            events.removeFirst(events.count - retainedEventCount)
        }
        return AppleRemoteChangeBatch(
            generation: generation,
            updatedIdentifiers: updated,
            deletedIdentifiers: deleted
        )
    }

    public func changes(after anchor: UInt64) throws -> AppleRemoteChangeBatch {
        guard anchor <= generation else {
            throw AppleRemoteChangeJournalError.expiredAnchor(anchor)
        }
        if anchor == generation {
            return AppleRemoteChangeBatch(generation: generation)
        }

        let oldestSupportedAnchor = events.first.map { $0.generation - 1 } ?? generation
        guard anchor >= oldestSupportedAnchor else {
            throw AppleRemoteChangeJournalError.expiredAnchor(anchor)
        }

        var touched = Set<String>()
        for event in events where event.generation > anchor {
            touched.formUnion(event.updated)
            touched.formUnion(event.deleted)
        }
        let updated = touched.filter { items[$0] != nil }.sorted()
        let deleted = touched.filter { items[$0] == nil }.sorted()
        return AppleRemoteChangeBatch(
            generation: generation,
            updatedIdentifiers: updated,
            deletedIdentifiers: deleted
        )
    }

    private static func snapshotOrder(
        _ lhs: AppleRemoteSnapshotItem,
        _ rhs: AppleRemoteSnapshotItem
    ) -> Bool {
        if lhs.path != rhs.path {
            return lhs.path < rhs.path
        }
        return lhs.revision < rhs.revision
    }

    private struct Event: Codable, Equatable, Sendable {
        var generation: UInt64
        var updated: [String]
        var deleted: [String]
    }
}

public final class AppleRemoteChangeJournalStore: @unchecked Sendable {
    private let fileURL: URL
    private let retainedEventCount: Int
    private let lock = NSLock()

    public init(fileURL: URL, retainedEventCount: Int = 64) {
        self.fileURL = fileURL
        self.retainedEventCount = retainedEventCount
    }

    public func load() throws -> AppleRemoteChangeJournal {
        lock.lock()
        defer { lock.unlock() }
        return try loadLocked()
    }

    @discardableResult
    public func reconcile(_ items: [AppleBridgeItem]) throws -> AppleRemoteChangeBatch {
        lock.lock()
        defer { lock.unlock() }
        var journal = try loadLocked()
        let batch = journal.reconcile(items)
        try persistLocked(journal)
        return batch
    }

    public func changes(after anchor: UInt64) throws -> AppleRemoteChangeBatch {
        lock.lock()
        defer { lock.unlock() }
        return try loadLocked().changes(after: anchor)
    }

    private func loadLocked() throws -> AppleRemoteChangeJournal {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return AppleRemoteChangeJournal(retainedEventCount: retainedEventCount)
        }
        return try JSONDecoder().decode(
            AppleRemoteChangeJournal.self,
            from: Data(contentsOf: fileURL)
        )
    }

    private func persistLocked(_ journal: AppleRemoteChangeJournal) throws {
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(journal).write(to: fileURL, options: .atomic)
    }
}
