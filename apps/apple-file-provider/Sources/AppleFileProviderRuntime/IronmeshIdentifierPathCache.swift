import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

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
