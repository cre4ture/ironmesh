import FileProvider
import XCTest
@testable import AppleCore

final class AppleItemVersionFingerprintTests: XCTestCase {
    func testMetadataVersionChangesWhenStableItemMoves() {
        let identifier = AppleFileProviderItemIdentifier.file(objectID: "stable-object-id")
        let original = item(path: "documents/report.txt", identifier: identifier)
        let moved = item(path: "archive/report.txt", identifier: identifier)

        XCTAssertNotEqual(
            AppleItemVersionFingerprint.metadataVersion(for: original),
            AppleItemVersionFingerprint.metadataVersion(for: moved)
        )
    }

    func testMetadataVersionIsRestartStableAndWithinFileProviderLimit() {
        let firstProcessItem = item(
            path: "documents/report.txt",
            identifier: .file(objectID: "stable-object-id")
        )
        let restartedProcessItem = item(
            path: "documents/report.txt",
            identifier: .file(objectID: "stable-object-id")
        )

        let firstVersion = AppleItemVersionFingerprint.metadataVersion(for: firstProcessItem)
        let restartedVersion = AppleItemVersionFingerprint.metadataVersion(for: restartedProcessItem)
        XCTAssertEqual(firstVersion, restartedVersion)
        XCTAssertLessThanOrEqual(firstVersion.count, 128)
    }

    func testMissingPostMoveRevisionRejectsCombinedMoveAndContentUpdate() {
        XCTAssertThrowsError(
            try ApplePostMoveRevisionPolicy.expectedRevision(
                metadataRevision: nil,
                includesContentUpdate: true,
                path: "archive/report.txt"
            )
        ) { error in
            let error = error as NSError
            XCTAssertEqual(error.domain, NSFileProviderErrorDomain)
            XCTAssertEqual(error.code, NSFileProviderError.Code.cannotSynchronize.rawValue)
            XCTAssertEqual(
                error.userInfo["IronmeshConflictReason"] as? String,
                "missing_post_move_revision"
            )
        }
    }

    func testMissingPostMoveRevisionRemainsAllowedForMoveWithoutContents() throws {
        XCTAssertNil(
            try ApplePostMoveRevisionPolicy.expectedRevision(
                metadataRevision: nil,
                includesContentUpdate: false,
                path: "archive/report.txt"
            )
        )
    }

    func testDeleteConflictUsesDeletionRejectedDisposition() {
        let error = ironmeshDeletionRejectedError(
            path: "documents/report.txt",
            expectedRevision: "v1",
            currentRevision: "v2"
        )

        XCTAssertEqual(error.domain, NSFileProviderErrorDomain)
        XCTAssertEqual(error.code, NSFileProviderError.Code.deletionRejected.rawValue)
        XCTAssertEqual(error.userInfo["IronmeshExpectedRevision"] as? String, "v1")
        XCTAssertEqual(error.userInfo["IronmeshCurrentRevision"] as? String, "v2")
    }

    func testDirectoryDeleteIsNotAdvertisedAndUsesSnapshotCASReason() {
        XCTAssertFalse(AppleDeletionCapabilityPolicy.allowsDeletion(for: .root))
        XCTAssertFalse(AppleDeletionCapabilityPolicy.allowsDeletion(for: .directory))
        XCTAssertTrue(AppleDeletionCapabilityPolicy.allowsDeletion(for: .file))
        XCTAssertTrue(AppleDeletionCapabilityPolicy.allowsDeletion(for: .temporaryFile))

        let error = ironmeshDeletionRejectedError(
            path: "documents",
            reason: "directory_snapshot_cas_required"
        )
        XCTAssertEqual(error.code, NSFileProviderError.Code.deletionRejected.rawValue)
        XCTAssertEqual(
            error.userInfo["IronmeshConflictReason"] as? String,
            "directory_snapshot_cas_required"
        )
    }

    func testConflictCopyErrorRequestsWorkingSetSignal() {
        let conflictError = ironmeshConflictError(
            originalPath: "documents/report.txt",
            conflictCopyPath: "documents/report (IronMesh conflict abc).txt",
            expectedRevision: "v1",
            currentRevision: "v2"
        )
        let moveError = ironmeshRevisionConflictError(
            path: "documents/report.txt",
            expectedRevision: "v1",
            currentRevision: "v2"
        )

        XCTAssertTrue(AppleWorkingSetSignalPolicy.shouldSignal(after: conflictError))
        XCTAssertFalse(AppleWorkingSetSignalPolicy.shouldSignal(after: moveError))
    }

    private func item(
        path: String,
        identifier: AppleFileProviderItemIdentifier
    ) -> AppleBridgeItem {
        AppleBridgeItem(
            path: path,
            displayName: normalizedPath(path).lastPathComponentOrFallback,
            identifier: identifier,
            kind: .file,
            revisionHint: "content-v1",
            sizeBytes: 42,
            modifiedAtUnix: 1_700_000_000
        )
    }
}
