import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

extension IronmeshFileProviderService {
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
            let result = try bridge.mkdir(path: pathMapper.remotePath(forLocalPath: destinationPath))
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
            path: pathMapper.remotePath(forLocalPath: destinationPath),
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
        contents url: URL?,
        expectedRevision: String?
    ) throws -> AppleBridgeItem {
        let currentItem = try item(for: identifier)
        guard currentItem.identifier.kind != .root else {
            throw unsupportedFeatureError("Modifying the provider root is not supported.")
        }

        if let expectedRevision,
           let currentRevision = currentItem.revisionHint,
           expectedRevision != currentRevision {
            if changedFields.contains(.contents) {
                let conflictCopyPath = AppleConflictCopyNaming.path(
                    originalPath: currentItem.path,
                    expectedRevision: expectedRevision,
                    currentRevision: currentRevision
                )
                _ = try bridge.upload(
                    path: pathMapper.remotePath(forLocalPath: conflictCopyPath),
                    data: try uploadData(from: url, allowMissingContents: false),
                    expectedRevision: nil
                )
                throw ironmeshConflictError(
                    originalPath: currentItem.path,
                    conflictCopyPath: conflictCopyPath,
                    expectedRevision: expectedRevision,
                    currentRevision: currentRevision
                )
            }
            throw ironmeshRevisionConflictError(
                path: currentItem.path,
                expectedRevision: expectedRevision,
                currentRevision: currentRevision
            )
        }

        var workingPath = currentItem.path
        var workingRevision = expectedRevision ?? currentItem.revisionHint
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
                do {
                    _ = try bridge.move(
                        from: pathMapper.remotePath(forLocalPath: currentItem.path),
                        to: pathMapper.remotePath(forLocalPath: destinationPath),
                        expectedRevision: workingRevision
                    )
                } catch {
                    try rethrowRevisionConflictIfRemoteChanged(
                        error,
                        localPath: currentItem.path,
                        expectedRevision: workingRevision
                    )
                }
                cache.movePathPrefix(from: currentItem.path, to: destinationPath)
                workingPath = destinationPath
                let postMoveRevision = try bridge.metadata(
                    pathOrIdentifier: pathMapper.remotePath(forLocalPath: destinationPath)
                )?.revisionHint
                workingRevision = try ApplePostMoveRevisionPolicy.expectedRevision(
                    metadataRevision: postMoveRevision,
                    includesContentUpdate: changedFields.contains(.contents),
                    path: destinationPath
                )
            }
        }

        if changedFields.contains(.contents) {
            guard currentItem.kind == .file, !contentType.conforms(to: .folder) else {
                throw unsupportedFeatureError("Directory content updates are not supported.")
            }

            let uploadData = try uploadData(from: url, allowMissingContents: false)
            let result = try uploadWithConflictRecovery(
                localPath: workingPath,
                data: uploadData,
                expectedRevision: workingRevision
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
        options: NSFileProviderDeleteItemOptions,
        expectedRevision: String?
    ) throws {
        _ = options
        do {
            let item = try item(for: identifier)
            guard item.identifier.kind != .root else {
                throw unsupportedFeatureError("Deleting the provider root is not supported.")
            }
            if let expectedRevision,
               let currentRevision = item.revisionHint,
               expectedRevision != currentRevision {
                throw deletionRejectedError(
                    for: item,
                    expectedRevision: expectedRevision,
                    currentRevision: currentRevision
                )
            }

            if item.kind == .directory {
                // A trailing-slash delete is recursive in the Rust client. A marker revision does
                // not cover children because ordinary child writes do not bump that marker.
                throw deletionRejectedError(
                    for: item,
                    reason: "directory_snapshot_cas_required"
                )
            }

            let result: AppleMutationResult
            do {
                result = try bridge.delete(
                    path: pathMapper.remotePath(forLocalPath: item.path),
                    expectedRevision: item.revisionHint
                )
            } catch {
                try rethrowDeletionConflictIfRemoteChanged(
                    error,
                    item: item,
                    expectedRevision: item.revisionHint
                )
            }
            if let conflictingRevision = result.conflictingRevision {
                throw deletionRejectedError(
                    for: refreshedItemForDeletion(item) ?? item,
                    expectedRevision: item.revisionHint ?? "unknown",
                    currentRevision: conflictingRevision
                )
            }
            cache.removeSubtree(at: item.path)
        } catch let error as NSError
            where error.domain == NSFileProviderErrorDomain
            && error.code == NSFileProviderError.Code.noSuchItem.rawValue {
            return
        }
    }
}
