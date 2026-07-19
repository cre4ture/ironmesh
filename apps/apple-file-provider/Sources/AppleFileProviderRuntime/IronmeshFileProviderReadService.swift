import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

extension IronmeshFileProviderService {
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
        let items = try bridge.list(path: pathMapper.remotePath(forLocalPath: path), depth: 1)
            .map(pathMapper.localItem)
            .filter { !$0.path.isEmpty }
        cache.record(items: items)
        return items
    }

    func reconcileRemoteChanges(after anchor: UInt64) throws -> (
        itemsByIdentifier: [String: AppleBridgeItem],
        batch: AppleRemoteChangeBatch
    ) {
        try connectIfNeeded()
        let profile = try currentProfile()
        let items = try bridge.list(
            path: pathMapper.remotePath(forLocalPath: ""),
            depth: profile.depth
        )
        .map(pathMapper.localItem)
        .filter { !$0.path.isEmpty }
        cache.record(items: items)
        _ = try changeJournal.reconcile(items)
        let batch = try changeJournal.changes(after: anchor)
        let itemsByIdentifier = items.reduce(into: [String: AppleBridgeItem]()) {
            result, item in
            let identifier = item.identifier.serialized
            if let existing = result[identifier], existing.path <= item.path {
                return
            }
            result[identifier] = item
        }
        return (itemsByIdentifier, batch)
    }

    func currentChangeGeneration() throws -> UInt64 {
        try changeJournal.load().generation
    }

    func item(for identifier: NSFileProviderItemIdentifier) throws -> AppleBridgeItem {
        if identifier == .rootContainer {
            return rootItem()
        }

        try connectIfNeeded()
        let appleIdentifier = try appleIdentifier(from: identifier)
        let lookupPath = try pathForLookup(identifier: appleIdentifier)
        let remoteLookupPath = pathMapper.remotePath(forLocalPath: lookupPath)
        let item = try bridge.metadata(pathOrIdentifier: remoteLookupPath + (appleIdentifier.kind == .directory && !remoteLookupPath.hasSuffix("/") ? "/" : ""))
            ?? { throw fileProviderError(.noSuchItem) }()
        let localItem = try pathMapper.localItem(from: item)
        cache.record(items: [localItem])
        return localItem
    }

    func fetchContents(for identifier: NSFileProviderItemIdentifier) throws -> (URL, AppleBridgeItem) {
        let item = try item(for: identifier)
        let appleIdentifier = try appleIdentifier(from: identifier)
        let lookupPath = try pathForLookup(identifier: appleIdentifier)
        let data = try bridge.download(
            path: pathMapper.remotePath(forLocalPath: lookupPath),
            revisionHint: item.revisionHint
        )

        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("IronMeshDownloads", isDirectory: true)
        try FileManager.default.createDirectory(at: temporaryDirectory, withIntermediateDirectories: true)
        let fileURL = temporaryDirectory.appendingPathComponent(UUID().uuidString + "-" + item.displayName)
        try data.write(to: fileURL, options: .atomic)
        return (fileURL, item)
    }
}
