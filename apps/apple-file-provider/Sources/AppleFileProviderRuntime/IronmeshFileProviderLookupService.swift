import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

extension IronmeshFileProviderService {
    func appleIdentifier(from identifier: NSFileProviderItemIdentifier) throws -> AppleFileProviderItemIdentifier {
        if identifier == .rootContainer {
            return .root
        }

        guard let parsed = AppleFileProviderItemIdentifier(serialized: identifier.rawValue) else {
            throw fileProviderError(.noSuchItem)
        }
        return parsed
    }

    func pathForLookup(identifier: AppleFileProviderItemIdentifier) throws -> String {
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

    func childPath(parentPath: String, filename: String) throws -> String {
        let normalizedParent = normalizedPath(parentPath)
        let leafName = try validatedLeafName(filename)
        guard !leafName.contains("/") else {
            throw mutationUsageError("The requested filename is invalid.")
        }
        return normalizedParent.isEmpty ? leafName : "\(normalizedParent)/\(leafName)"
    }

    func mutationDestinationPath(
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

    func resolvedItem(
        after result: AppleMutationResult,
        at path: String,
        kind: AppleFileProviderItemKind
    ) throws -> AppleBridgeItem {
        guard result.accepted else {
            throw unsupportedFeatureError(result.message ?? "The Apple bridge rejected the mutation.")
        }

        let metadataPath = normalizedPath(path)
        let remoteBasePath = pathMapper.remotePath(forLocalPath: metadataPath)
        let remoteMetadataPath = kind == .directory ? "\(remoteBasePath)/" : remoteBasePath
        if let remoteItem = try? bridge.metadata(pathOrIdentifier: remoteMetadataPath),
           let item = try? pathMapper.localItem(from: remoteItem) {
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

    func resolvedIdentifier(
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

    func uploadData(from url: URL?, allowMissingContents: Bool) throws -> Data {
        guard let url else {
            if allowMissingContents {
                return Data()
            }
            throw mutationUsageError("The Apple File Provider did not receive file contents for this update.")
        }
        return try Data(contentsOf: url)
    }
}
