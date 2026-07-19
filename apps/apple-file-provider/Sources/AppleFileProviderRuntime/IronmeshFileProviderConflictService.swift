import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

extension IronmeshFileProviderService {
    func uploadWithConflictRecovery(
        localPath: String,
        data: Data,
        expectedRevision: String?
    ) throws -> AppleMutationResult {
        let remotePath = pathMapper.remotePath(forLocalPath: localPath)
        let result: AppleMutationResult
        do {
            result = try bridge.upload(
                path: remotePath,
                data: data,
                expectedRevision: expectedRevision
            )
        } catch {
            guard let expectedRevision else {
                throw error
            }
            let currentRevision: String?
            do {
                currentRevision = try bridge.metadata(pathOrIdentifier: remotePath)?.revisionHint
            } catch {
                throw error
            }
            guard let currentRevision, currentRevision != expectedRevision else {
                throw error
            }
            try materializeConflictCopy(
                localPath: localPath,
                data: data,
                expectedRevision: expectedRevision,
                currentRevision: currentRevision
            )
        }

        if let expectedRevision, let conflictingRevision = result.conflictingRevision {
            try materializeConflictCopy(
                localPath: localPath,
                data: data,
                expectedRevision: expectedRevision,
                currentRevision: conflictingRevision
            )
        }
        return result
    }

    func materializeConflictCopy(
        localPath: String,
        data: Data,
        expectedRevision: String,
        currentRevision: String
    ) throws -> Never {
        let conflictCopyPath = AppleConflictCopyNaming.path(
            originalPath: localPath,
            expectedRevision: expectedRevision,
            currentRevision: currentRevision
        )
        _ = try bridge.upload(
            path: pathMapper.remotePath(forLocalPath: conflictCopyPath),
            data: data,
            expectedRevision: nil
        )
        throw ironmeshConflictError(
            originalPath: localPath,
            conflictCopyPath: conflictCopyPath,
            expectedRevision: expectedRevision,
            currentRevision: currentRevision
        )
    }

    func rethrowRevisionConflictIfRemoteChanged(
        _ originalError: Error,
        localPath: String,
        expectedRevision: String?,
        isDirectory: Bool = false
    ) throws -> Never {
        guard let expectedRevision else {
            throw originalError
        }
        let remoteBasePath = pathMapper.remotePath(forLocalPath: localPath)
        let remotePath = isDirectory ? "\(remoteBasePath)/" : remoteBasePath
        let currentRevision: String?
        do {
            currentRevision = try bridge.metadata(pathOrIdentifier: remotePath)?.revisionHint
        } catch {
            throw originalError
        }
        guard let currentRevision, currentRevision != expectedRevision else {
            throw originalError
        }
        throw ironmeshRevisionConflictError(
            path: localPath,
            expectedRevision: expectedRevision,
            currentRevision: currentRevision
        )
    }

    func rethrowDeletionConflictIfRemoteChanged(
        _ originalError: Error,
        item: AppleBridgeItem,
        expectedRevision: String?
    ) throws -> Never {
        guard let expectedRevision else {
            throw originalError
        }
        let remotePath = pathMapper.remotePath(forLocalPath: item.path)
        let remoteItem: AppleBridgeItem?
        do {
            remoteItem = try bridge.metadata(pathOrIdentifier: remotePath)
        } catch {
            throw originalError
        }
        guard let remoteItem,
              let currentRevision = remoteItem.revisionHint,
              currentRevision != expectedRevision else {
            throw originalError
        }
        let localItem = (try? pathMapper.localItem(from: remoteItem)) ?? item
        throw deletionRejectedError(
            for: localItem,
            expectedRevision: expectedRevision,
            currentRevision: currentRevision
        )
    }

    func refreshedItemForDeletion(_ item: AppleBridgeItem) -> AppleBridgeItem? {
        let remotePath = pathMapper.remotePath(forLocalPath: item.path)
        guard let remoteItem = try? bridge.metadata(pathOrIdentifier: remotePath) else {
            return nil
        }
        return try? pathMapper.localItem(from: remoteItem)
    }

    func deletionRejectedError(
        for item: AppleBridgeItem,
        expectedRevision: String? = nil,
        currentRevision: String? = nil,
        reason: String = "remote_revision_changed"
    ) -> NSError {
        let updatedVersion = IronmeshFileProviderItem(
            bridgeItem: item,
            domainDisplayName: configuration.domainDisplayName
        )
        let sdkError = NSError.fileProviderErrorForRejectedDeletion(of: updatedVersion)
        var userInfo = sdkError.userInfo
        userInfo["IronmeshConflictReason"] = reason
        userInfo["IronmeshExpectedRevision"] = expectedRevision
        userInfo["IronmeshCurrentRevision"] = currentRevision
        return NSError(domain: sdkError.domain, code: sdkError.code, userInfo: userInfo)
    }

    func validatedLeafName(_ value: String) throws -> String {
        guard let trimmed = value.nilIfBlank else {
            throw mutationUsageError("The Apple File Provider requires a non-empty filename.")
        }
        return trimmed
    }
}
