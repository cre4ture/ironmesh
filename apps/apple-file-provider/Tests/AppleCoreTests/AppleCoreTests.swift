import XCTest
@testable import AppleCore

final class AppleCoreTests: XCTestCase {
    func testRootSnapshotRefreshDoesNotBecomeCurrentDirectoryWhenBrowsingNestedPath() {
        var coordinator = AppleDirectoryLoadCoordinator()

        let rootRefresh = coordinator.begin(path: "", updatesCurrentDirectory: false)

        XCTAssertTrue(coordinator.acceptsRootSnapshot(rootRefresh))
        XCTAssertFalse(coordinator.acceptsCurrentDirectory(rootRefresh))
        XCTAssertTrue(coordinator.acceptsAnyResult(from: rootRefresh))
    }

    func testCurrentDirectoryRefreshUpdatesItemsWithoutReplacingPath() {
        var coordinator = AppleDirectoryLoadCoordinator()

        let refresh = coordinator.begin(
            path: "documents",
            updatesCurrentDirectory: true,
            updatesCurrentPath: false
        )

        XCTAssertTrue(coordinator.acceptsCurrentDirectory(refresh))
        XCTAssertFalse(refresh.updatesCurrentPath)
        XCTAssertTrue(coordinator.acceptsSharedState(refresh))
    }

    func testNewerDirectoryNavigationSupersedesOlderResult() {
        var coordinator = AppleDirectoryLoadCoordinator()

        let documents = coordinator.begin(
            path: "documents",
            updatesCurrentDirectory: true,
            updatesCurrentPath: true
        )
        let photos = coordinator.begin(
            path: "photos",
            updatesCurrentDirectory: true,
            updatesCurrentPath: true
        )

        XCTAssertFalse(coordinator.acceptsCurrentDirectory(documents))
        XCTAssertFalse(coordinator.acceptsAnyResult(from: documents))
        XCTAssertTrue(coordinator.acceptsCurrentDirectory(photos))
    }

    func testRootRefreshCanUpdateSnapshotAfterNewerNestedNavigationWithoutReplacingDirectory() {
        var coordinator = AppleDirectoryLoadCoordinator()

        let rootRefresh = coordinator.begin(
            path: "",
            updatesCurrentDirectory: true,
            updatesCurrentPath: true
        )
        let nestedNavigation = coordinator.begin(
            path: "documents",
            updatesCurrentDirectory: true,
            updatesCurrentPath: true
        )

        XCTAssertTrue(coordinator.acceptsRootSnapshot(rootRefresh))
        XCTAssertFalse(coordinator.acceptsCurrentDirectory(rootRefresh))
        XCTAssertTrue(coordinator.acceptsAnyResult(from: rootRefresh))
        XCTAssertFalse(coordinator.acceptsSharedState(rootRefresh))
        XCTAssertTrue(coordinator.acceptsCurrentDirectory(nestedNavigation))
        XCTAssertTrue(coordinator.acceptsSharedState(nestedNavigation))
    }

    func testNewerRootRefreshSupersedesOlderRootSnapshot() {
        var coordinator = AppleDirectoryLoadCoordinator()

        let olderRefresh = coordinator.begin(path: "", updatesCurrentDirectory: false)
        let newerRefresh = coordinator.begin(path: "/", updatesCurrentDirectory: false)

        XCTAssertFalse(coordinator.acceptsRootSnapshot(olderRefresh))
        XCTAssertFalse(coordinator.acceptsAnyResult(from: olderRefresh))
        XCTAssertTrue(coordinator.acceptsRootSnapshot(newerRefresh))
    }

    func testInvalidationRejectsOutstandingDirectoryLoads() {
        var coordinator = AppleDirectoryLoadCoordinator()
        let request = coordinator.begin(path: "documents", updatesCurrentDirectory: true)

        coordinator.invalidate()

        XCTAssertFalse(coordinator.acceptsAnyResult(from: request))
    }

    func testConnectionContextResetInvalidatesNestedResultAndReloadsRootAsCurrentDirectory() {
        var coordinator = AppleDirectoryLoadCoordinator()
        let staleNestedRequest = coordinator.begin(
            path: "documents",
            updatesCurrentDirectory: true,
            updatesCurrentPath: true
        )

        let rootRequest = coordinator.beginConnectionContextReset()

        XCTAssertFalse(coordinator.acceptsAnyResult(from: staleNestedRequest))
        XCTAssertEqual(rootRequest.path, "")
        XCTAssertTrue(rootRequest.updatesRootSnapshot)
        XCTAssertTrue(rootRequest.updatesCurrentDirectory)
        XCTAssertTrue(rootRequest.updatesCurrentPath)
        XCTAssertTrue(coordinator.acceptsRootSnapshot(rootRequest))
        XCTAssertTrue(coordinator.acceptsCurrentDirectory(rootRequest))
        XCTAssertTrue(coordinator.acceptsSharedState(rootRequest))
    }

    func testConnectionInputNormalizationAddsHttpSchemeAndSlash() {
        let configuration = AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080")
        XCTAssertEqual(configuration.normalizedConnectionInput, "http://127.0.0.1:18080/")
    }

    func testConnectionInputKeepsBootstrapJsonUntouched() {
        let json = #"{"version":1}"#
        let configuration = AppleConnectionConfiguration(connectionInput: json)
        XCTAssertEqual(configuration.normalizedConnectionInput, json)
    }

    func testBridgeItemDerivesDisplayNameFromPath() {
        let item = AppleBridgeItem(
            path: "docs/readme.txt",
            displayName: "",
            identifier: .directory(path: "docs"),
            kind: .file
        )

        XCTAssertEqual(item.displayName, "readme.txt")
    }

    func testConflictStatePreservesReasonAndRevisions() {
        let state = AppleConflictState(
            status: .conflicted,
            reason: .modifyDelete,
            preferredRevision: "v-preferred",
            alternateRevisions: ["v-alt-1", " ", "\n"],
            conflictCopyPath: "docs/conflicts/readme.txt"
        )

        XCTAssertEqual(state.status, .conflicted)
        XCTAssertEqual(state.reason, .modifyDelete)
        XCTAssertEqual(state.preferredRevision, "v-preferred")
        XCTAssertEqual(state.alternateRevisions, ["v-alt-1"])
        XCTAssertEqual(state.conflictCopyPath, "docs/conflicts/readme.txt")
    }

    func testStoredConnectionStateFallsBackToBundleDefaults() {
        let fallback = AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080")
        let stored = AppleStoredConnectionState(clientIdentityJSON: #"{"device_id":"abc"}"#)

        let effective = stored.effectiveConfiguration(fallback: fallback)

        XCTAssertEqual(effective.connectionInput, "127.0.0.1:18080")
        XCTAssertEqual(effective.clientIdentityJSON, #"{"device_id":"abc"}"#)
    }

    func testConnectionSettingsStoreRoundTripsSavedState() throws {
        let suiteName = "AppleCoreTests.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            XCTFail("Expected isolated test defaults")
            return
        }
        defaults.removePersistentDomain(forName: suiteName)

        let store = AppleConnectionSettingsStore(defaults: defaults)
        let state = AppleStoredConnectionState(
            connectionInput: #"{"version":1}"#,
            serverCAPem: "demo-ca",
            clientIdentityJSON: #"{"device_id":"device-1"}"#,
            deviceID: "device-1",
            deviceLabel: "Phone",
            bootstrapInputDraft: #"{"claim":true}"#
        )

        try store.save(state)

        XCTAssertEqual(store.load(), state)
        store.clear()
        XCTAssertNil(store.load())
    }

    func testEnrollmentResultBuildsClientIdentityJSONWhenMissing() throws {
        let enrollment = AppleBootstrapEnrollmentResult(
            clusterID: "cluster-1",
            connectionBootstrapJSON: #"{"version":1}"#,
            deviceID: "device-1",
            label: "Phone",
            publicKeyPEM: "public-key",
            privateKeyPEM: "private-key",
            credentialPEM: "credential",
            rendezvousClientIdentityPEM: "rendezvous",
            serverBaseURL: "https://example.test/",
            serverCAPem: "ca",
            createdAtUnix: 123,
            expiresAtUnix: 456
        )

        let json = try enrollment.resolvedClientIdentityJSON()
        let decoded = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]

        XCTAssertEqual(decoded?["cluster_id"] as? String, "cluster-1")
        XCTAssertEqual(decoded?["device_id"] as? String, "device-1")
        XCTAssertEqual(decoded?["credential_pem"] as? String, "credential")
        XCTAssertEqual(decoded?["rendezvous_client_identity_pem"] as? String, "rendezvous")
    }

    func testEnrollmentResultDecodesDeviceLabelAlias() throws {
        let json = #"""
        {
          "cluster_id": "cluster-1",
          "device_id": "device-1",
          "device_label": "Phone",
          "public_key_pem": "public-key",
          "private_key_pem": "private-key",
          "credential_pem": "credential"
        }
        """#

        let enrollment = try JSONDecoder().decode(
            AppleBootstrapEnrollmentResult.self,
            from: Data(json.utf8)
        )

        XCTAssertEqual(enrollment.label, "Phone")
    }
}
