import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

final class IronmeshFileProviderItem: NSObject, NSFileProviderItem {
    private let bridgeItem: AppleBridgeItem
    private let domainDisplayName: String

    init(
        bridgeItem: AppleBridgeItem,
        domainDisplayName: String
    ) {
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
        var capabilities: NSFileProviderItemCapabilities
        switch bridgeItem.identifier.kind {
        case .root:
            capabilities = [.allowsReading, .allowsWriting]
        case .directory:
            capabilities = [.allowsReading, .allowsWriting]
        case .file, .temporaryFile:
            capabilities = [
                .allowsReading,
                .allowsWriting,
                .allowsRenaming,
                .allowsReparenting,
            ]
        }
        if AppleDeletionCapabilityPolicy.allowsDeletion(for: bridgeItem.identifier.kind) {
            capabilities.insert(.allowsDeleting)
        }
        capabilities.insert(.allowsEvicting)
        return capabilities
    }

    var contentPolicy: NSFileProviderContentPolicy {
        bridgeItem.identifier.kind == .root
            ? .downloadLazilyAndEvictOnRemoteUpdate
            : .inherited
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
        let metadata = AppleItemVersionFingerprint.metadataVersion(for: bridgeItem)
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
