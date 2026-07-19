import Foundation
import XCTest
@testable import AppleCore

final class AppleSyncProfilesTests: XCTestCase {
    func testManagedDomainWithoutProfileFailsClosedInsteadOfExposingRemoteRoot() {
        XCTAssertThrowsError(
            try AppleSyncProfileResolution.resolve(
                domainIdentifier: "dev.ironmesh.profile.orphaned",
                storedProfile: nil,
                configuredProfile: nil,
                legacyDisplayName: "Orphaned"
            )
        ) { error in
            XCTAssertEqual(
                error as? AppleSyncProfileResolutionError,
                .missingManagedProfile("dev.ironmesh.profile.orphaned")
            )
        }
    }

    func testManagedDomainWithoutStoredProfileIgnoresStaleConfiguredProfile() {
        let staleProfile = AppleSyncProfile(id: "removed", displayName: "Removed")

        XCTAssertThrowsError(
            try AppleSyncProfileResolution.resolve(
                domainIdentifier: staleProfile.domainIdentifier,
                storedProfile: nil,
                configuredProfile: staleProfile,
                legacyDisplayName: staleProfile.displayName
            )
        ) { error in
            XCTAssertEqual(
                error as? AppleSyncProfileResolutionError,
                .missingManagedProfile(staleProfile.domainIdentifier)
            )
        }
    }

    func testLegacyDomainRetainsExplicitUnrestrictedFallback() throws {
        let profile = try AppleSyncProfileResolution.resolve(
            domainIdentifier: "dev.ironmesh.default",
            storedProfile: nil,
            configuredProfile: nil,
            legacyDisplayName: "Legacy"
        )

        XCTAssertEqual(profile.remotePrefix, "")
        XCTAssertTrue(profile.networkPolicy.allowsExpensiveNetwork)
        XCTAssertTrue(profile.networkPolicy.allowsConstrainedNetwork)
        XCTAssertFalse(profile.powerPolicy.defersInLowPowerMode)
    }

    func testProfileStorePersistsMultipleScopesAndLifecycleAcrossRestart() throws {
        let suiteName = "AppleSyncProfilesTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let firstStore = AppleSyncProfileStore(defaults: defaults)
        let documents = AppleSyncProfile(
            id: "documents",
            displayName: "Documents",
            remotePrefix: "team/documents"
        )
        let photos = AppleSyncProfile(
            id: "photos",
            displayName: "Photos",
            remotePrefix: "camera/uploads",
            networkPolicy: AppleSyncProfileNetworkPolicy(
                allowsExpensiveNetwork: true,
                allowsConstrainedNetwork: false
            )
        )

        try firstStore.upsert(documents)
        try firstStore.upsert(photos)
        try firstStore.setLifecycle(.paused, profileID: photos.id)

        let restartedStore = AppleSyncProfileStore(defaults: defaults)
        let restartedProfiles = try restartedStore.load()
        XCTAssertEqual(restartedProfiles.count, 2)
        XCTAssertEqual(
            restartedProfiles.first(where: { $0.id == "documents" })?.remotePrefix,
            "team/documents"
        )
        XCTAssertEqual(
            restartedProfiles.first(where: { $0.id == "photos" })?.lifecycle,
            .paused
        )
        XCTAssertEqual(
            restartedProfiles.first(where: { $0.id == "photos" })?.connectionReference,
            .sharedDevice
        )

        try restartedStore.setLifecycle(.active, profileID: photos.id)
        try restartedStore.remove(profileID: documents.id)
        XCTAssertEqual(try restartedStore.load().map(\.id), ["photos"])
        XCTAssertEqual(try restartedStore.load().first?.lifecycle, .active)
    }

    func testProfilePathMapperKeepsEachDomainInsideItsRemotePrefix() throws {
        let mapper = AppleProfilePathMapper(remotePrefix: "/team/documents/")
        let remoteItem = item(
            path: "team/documents/reports/q2.txt",
            identifier: .temporaryFile(path: "team/documents/reports/q2.txt"),
            revision: "v2"
        )

        XCTAssertEqual(mapper.remotePath(forLocalPath: "reports/q2.txt"), "team/documents/reports/q2.txt")
        let localItem = try mapper.localItem(from: remoteItem)
        XCTAssertEqual(localItem.path, "reports/q2.txt")
        XCTAssertEqual(localItem.identifier, .temporaryFile(path: "reports/q2.txt"))
        XCTAssertThrowsError(try mapper.localPath(forRemotePath: "another-scope/file.txt"))
    }

    func testNetworkAndPowerRestrictionsBlockThenAllowOfflineRecovery() {
        let profile = AppleSyncProfile(
            id: "restricted",
            displayName: "Restricted",
            networkPolicy: AppleSyncProfileNetworkPolicy(
                allowsExpensiveNetwork: false,
                allowsConstrainedNetwork: false
            ),
            powerPolicy: AppleSyncProfilePowerPolicy(defersInLowPowerMode: true)
        )

        XCTAssertEqual(
            AppleSyncConstraintEvaluator.evaluate(
                profile: profile,
                environment: AppleSyncEnvironmentSnapshot(isConnected: false)
            ),
            .blocked("No network connection is currently available.")
        )
        XCTAssertFalse(
            AppleSyncConstraintEvaluator.evaluate(
                profile: profile,
                environment: AppleSyncEnvironmentSnapshot(isConnected: true, isExpensive: true)
            ).isAllowed
        )
        XCTAssertFalse(
            AppleSyncConstraintEvaluator.evaluate(
                profile: profile,
                environment: AppleSyncEnvironmentSnapshot(
                    isConnected: true,
                    isLowPowerModeEnabled: true
                )
            ).isAllowed
        )
        XCTAssertEqual(
            AppleSyncConstraintEvaluator.evaluate(
                profile: profile,
                environment: AppleSyncEnvironmentSnapshot(isConnected: true)
            ),
            .allowed
        )
    }

    func testPausedProfileIsBlockedIndependentlyOfNetwork() {
        let profile = AppleSyncProfile(
            id: "paused",
            displayName: "Paused",
            lifecycle: .paused,
            networkPolicy: AppleSyncProfileNetworkPolicy(
                allowsExpensiveNetwork: true,
                allowsConstrainedNetwork: true
            ),
            powerPolicy: AppleSyncProfilePowerPolicy(defersInLowPowerMode: false)
        )

        XCTAssertEqual(
            AppleSyncConstraintEvaluator.evaluate(
                profile: profile,
                environment: AppleSyncEnvironmentSnapshot(
                    isConnected: true,
                    isExpensive: true,
                    isConstrained: true,
                    isLowPowerModeEnabled: true
                )
            ),
            .blocked("This sync profile is paused.")
        )
    }

    func testConflictCopyNameIsDeterministicAndIncludesBaseVersion() {
        let first = AppleConflictCopyNaming.path(
            originalPath: "docs/readme.txt",
            expectedRevision: "base-v1",
            currentRevision: "remote-v2"
        )
        let retry = AppleConflictCopyNaming.path(
            originalPath: "docs/readme.txt",
            expectedRevision: "base-v1",
            currentRevision: "remote-v2"
        )
        let differentBase = AppleConflictCopyNaming.path(
            originalPath: "docs/readme.txt",
            expectedRevision: "base-v0",
            currentRevision: "remote-v2"
        )

        XCTAssertEqual(first, retry)
        XCTAssertNotEqual(first, differentBase)
        XCTAssertTrue(first.hasPrefix("docs/readme (IronMesh conflict "))
        XCTAssertTrue(first.hasSuffix(".txt"))
    }

    func testChangeJournalReportsConcurrentUpdatesAndRemoteDeletes() throws {
        var journal = AppleRemoteChangeJournal()
        let original = item(path: "docs/readme.txt", revision: "v1")
        let initial = journal.reconcile([original])
        XCTAssertEqual(initial.updatedIdentifiers, [original.identifier.serialized])

        let updated = item(path: "docs/readme.txt", revision: "v2")
        let concurrent = item(path: "docs/readme (IronMesh conflict abc).txt", revision: "conflict-v1")
        let changed = journal.reconcile([updated, concurrent])
        XCTAssertEqual(
            changed.updatedIdentifiers,
            [concurrent.identifier.serialized, updated.identifier.serialized].sorted()
        )

        let deleted = journal.reconcile([concurrent])
        XCTAssertEqual(deleted.deletedIdentifiers, [original.identifier.serialized])

        let changesSinceInitial = try journal.changes(after: initial.generation)
        XCTAssertEqual(changesSinceInitial.updatedIdentifiers, [concurrent.identifier.serialized])
        XCTAssertEqual(changesSinceInitial.deletedIdentifiers, [original.identifier.serialized])
    }

    func testChangeJournalStoreResumesAfterExtensionRestartAndOfflineGap() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("AppleSyncProfilesTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("journal.json")
        let firstStore = AppleRemoteChangeJournalStore(fileURL: fileURL)
        let original = item(path: "offline.txt", revision: "v1")
        let initial = try firstStore.reconcile([original])

        // No reconcile occurs while policy evaluation blocks the remote request. A new extension
        // process later reads the same anchor and observes the complete remote delta.
        let restartedStore = AppleRemoteChangeJournalStore(fileURL: fileURL)
        let recovered = item(path: "offline.txt", revision: "v2")
        let added = item(path: "new-after-offline.txt", revision: "v1")
        try restartedStore.reconcile([recovered, added])

        let pending = try restartedStore.changes(after: initial.generation)
        XCTAssertEqual(
            pending.updatedIdentifiers,
            [recovered.identifier.serialized, added.identifier.serialized].sorted()
        )
        XCTAssertTrue(pending.deletedIdentifiers.isEmpty)
    }

    private func item(
        path: String,
        identifier: AppleFileProviderItemIdentifier? = nil,
        revision: String
    ) -> AppleBridgeItem {
        AppleBridgeItem(
            path: path,
            displayName: "",
            identifier: identifier ?? .temporaryFile(path: path),
            kind: .file,
            revisionHint: revision
        )
    }
}
