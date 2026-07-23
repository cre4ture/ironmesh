import AppleCore
import AppleFileProviderShared
@preconcurrency import FileProvider
import XCTest

final class IronmeshIosProjectTests: XCTestCase {
    func testRevisionConflictMapsToCannotSynchronizeWithCurrentRevision() {
        let error = ironmeshRevisionConflictError(
            path: "docs/readme.txt",
            expectedRevision: "version-1",
            currentRevision: "version-2"
        )

        XCTAssertEqual(error.domain, NSFileProviderErrorDomain)
        XCTAssertEqual(error.code, NSFileProviderError.Code.cannotSynchronize.rawValue)
        XCTAssertEqual(error.userInfo["IronmeshCurrentRevision"] as? String, "version-2")
    }

    func testSharedPackageTypesAreAvailableToTheXcodeProject() {
        let configuration = AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080")
        let item = AppleFileProviderItem.file(
            path: "docs/readme.txt",
            objectID: "demo-object-id"
        )

        XCTAssertEqual(configuration.normalizedConnectionInput, "http://127.0.0.1:18080/")
        XCTAssertEqual(item.identifier.serialized, "file:object:demo-object-id")
    }

    func testBootstrapPayloadTakesPrecedenceForEffectiveConnection() {
        let draft = IronmeshConnectionDraft(
            directConnectionInput: "10.0.0.8:8080",
            bootstrapInput: "{\"cluster\":true}"
        )

        XCTAssertEqual(draft.effectiveConnectionInput, "{\"cluster\":true}")
        XCTAssertEqual(draft.normalizedConnectionInput, "{\"cluster\":true}")
    }

    func testScannedConnectionPayloadExtractsCustomSchemeBootstrap() {
        let scanned = "ironmesh://import?payload=%7B%22cluster%22%3Atrue%7D"

        XCTAssertEqual(
            IronmeshConnectionDraft.scannedConnectionPayload(from: scanned),
            "{\"cluster\":true}"
        )
    }

    func testApplyScannedCodeStoresDirectRouteWhenNeeded() {
        var draft = IronmeshConnectionDraft()

        let applied = draft.applyScannedCode("storage.internal:9443")

        XCTAssertTrue(applied)
        XCTAssertEqual(draft.directConnectionInput, "storage.internal:9443")
        XCTAssertEqual(draft.normalizedConnectionInput, "http://storage.internal:9443/")
    }

    func testEnrollmentSummaryReflectsIdentityAndBootstrap() {
        let directOnly = IronmeshConnectionDraft(directConnectionInput: "127.0.0.1:8080")
        let bootstrapAndIdentity = IronmeshConnectionDraft(
            bootstrapInput: "{\"claim\":true}",
            clientIdentityJSON: "{\"device_id\":\"ios-demo\"}"
        )

        XCTAssertEqual(directOnly.enrollmentSummary, "Direct route configured.")
        XCTAssertEqual(
            bootstrapAndIdentity.enrollmentSummary,
            "Bootstrap bundle imported and client identity attached."
        )
    }

    func testBootstrapWithoutIdentityRequiresEnrollment() {
        let needsEnrollment = IronmeshConnectionDraft(
            bootstrapInput: "{\"cluster\":true}"
        )
        let ready = IronmeshConnectionDraft(
            bootstrapInput: "{\"cluster\":true}",
            clientIdentityJSON: "{\"device_id\":\"ios-demo\"}"
        )

        XCTAssertTrue(needsEnrollment.requiresEnrollment)
        XCTAssertFalse(ready.requiresEnrollment)
    }

    func testPersistedBootstrapClaimStillRequiresEnrollmentWhenIdentityExists() {
        let compactClaim = #"{"v":1,"k":"client_bootstrap_claim","c":"cluster","n":"node","r":[],"t":"token"}"#
        let draft = IronmeshConnectionDraft(
            bootstrapInput: compactClaim,
            clientIdentityJSON: #"{"device_id":"ios-demo"}"#
        )

        XCTAssertTrue(IronmeshConnectionDraft.looksLikeBootstrapClaim(compactClaim))
        XCTAssertTrue(draft.requiresEnrollment)
    }

    func testFileProviderDomainRefreshReportsMissingDomain() async {
        let coordinator = AppleFileProviderDomainCoordinator(
            manager: MockFileProviderDomainManager()
        )

        let state = await coordinator.refresh(expectedIdentifier: "dev.ironmesh.default")

        XCTAssertEqual(state, .missing)
    }

    func testFileProviderDomainRegisterCreatesNewDomain() async {
        let manager = MockFileProviderDomainManager()
        let coordinator = AppleFileProviderDomainCoordinator(manager: manager)

        let result = await coordinator.register(
            identifier: "dev.ironmesh.default",
            displayName: "IronMesh"
        )

        XCTAssertEqual(
            result,
            AppleFileProviderDomainRegistrationResult(
                state: .registered(displayName: "IronMesh"),
                identifier: "dev.ironmesh.default",
                wasCreated: true
            )
        )
        let addedDomains = await manager.recordedAdds()
        XCTAssertEqual(
            addedDomains,
            [AppleRegisteredFileProviderDomain(identifier: "dev.ironmesh.default", displayName: "IronMesh")]
        )
    }

    func testFileProviderDomainRegisterAvoidsDuplicateAddWhenAlreadyRegistered() async {
        let manager = MockFileProviderDomainManager(
            domainsToReturn: [
                AppleRegisteredFileProviderDomain(
                    identifier: "dev.ironmesh.default",
                    displayName: "Existing IronMesh"
                )
            ]
        )
        let coordinator = AppleFileProviderDomainCoordinator(manager: manager)

        let result = await coordinator.register(
            identifier: "dev.ironmesh.default",
            displayName: "IronMesh"
        )

        XCTAssertEqual(
            result,
            AppleFileProviderDomainRegistrationResult(
                state: .registered(displayName: "Existing IronMesh"),
                identifier: "dev.ironmesh.default",
                wasCreated: false
            )
        )
        let addedDomains = await manager.recordedAdds()
        XCTAssertTrue(addedDomains.isEmpty)
    }

    func testFileProviderDomainRegisterTreatsDuplicateFailureAsSuccess() async {
        let manager = MockFileProviderDomainManager(
            addError: MockDomainError("Domain already exists."),
            postAddDomains: [
                AppleRegisteredFileProviderDomain(
                    identifier: "dev.ironmesh.default",
                    displayName: "IronMesh"
                )
            ]
        )
        let coordinator = AppleFileProviderDomainCoordinator(manager: manager)

        let result = await coordinator.register(
            identifier: "dev.ironmesh.default",
            displayName: "IronMesh"
        )

        XCTAssertEqual(
            result,
            AppleFileProviderDomainRegistrationResult(
                state: .registered(displayName: "IronMesh"),
                identifier: "dev.ironmesh.default",
                wasCreated: false
            )
        )
    }

    func testSyncProfileDomainConfigureIsIdempotent() async throws {
        let profile = AppleSyncProfile(id: "documents", displayName: "Documents")
        let manager = MockFileProviderDomainManager(
            domainsToReturn: [
                AppleRegisteredFileProviderDomain(
                    identifier: profile.domainIdentifier,
                    displayName: profile.displayName
                )
            ]
        )
        let coordinator = AppleSyncProfileDomainCoordinator(manager: manager)

        try await coordinator.configure(profile)

        let adds = await manager.recordedAdds()
        XCTAssertTrue(adds.isEmpty)
    }

    func testSyncProfileDomainPauseResumeSignalAndRemove() async throws {
        let profile = AppleSyncProfile(id: "photos", displayName: "Photos")
        let manager = MockFileProviderDomainManager(
            domainsToReturn: [
                AppleRegisteredFileProviderDomain(
                    identifier: profile.domainIdentifier,
                    displayName: profile.displayName
                )
            ]
        )
        let coordinator = AppleSyncProfileDomainCoordinator(manager: manager)

        try await coordinator.pause(profile)
        try await coordinator.resume(profile)
        try await coordinator.remove(profile)

        let operations = await manager.recordedLifecycleOperations()
        XCTAssertEqual(
            operations,
            [
                "disconnect:\(profile.domainIdentifier)",
                "reconnect:\(profile.domainIdentifier)",
                "signal:\(profile.domainIdentifier)",
                "remove:\(profile.domainIdentifier)",
            ]
        )
    }

    func testSyncProfileResumeRecreatesMissingDomainAsActive() async throws {
        let pausedProfile = AppleSyncProfile(
            id: "missing-paused",
            displayName: "Missing paused",
            lifecycle: .paused
        )
        let manager = MockFileProviderDomainManager()
        let coordinator = AppleSyncProfileDomainCoordinator(manager: manager)

        try await coordinator.resume(pausedProfile)

        let adds = await manager.recordedAdds()
        XCTAssertEqual(
            adds,
            [
                AppleRegisteredFileProviderDomain(
                    identifier: pausedProfile.domainIdentifier,
                    displayName: pausedProfile.displayName
                )
            ]
        )
        let operations = await manager.recordedLifecycleOperations()
        XCTAssertTrue(operations.isEmpty)
    }

    func testSyncProfileRemoveMissingDomainIsIdempotent() async throws {
        let profile = AppleSyncProfile(id: "already-removed", displayName: "Already removed")
        let manager = MockFileProviderDomainManager()
        let coordinator = AppleSyncProfileDomainCoordinator(manager: manager)

        try await coordinator.remove(profile)

        let operations = await manager.recordedLifecycleOperations()
        XCTAssertTrue(operations.isEmpty)
    }

    func testRegisteredProfilesDeduplicatesLegacyDomainsDeterministically() async throws {
        let profile = AppleSyncProfile(id: "duplicate", displayName: "Duplicate")
        let manager = MockFileProviderDomainManager(
            domainsToReturn: [
                AppleRegisteredFileProviderDomain(
                    identifier: profile.domainIdentifier,
                    displayName: "Zulu",
                    isDisconnected: false
                ),
                AppleRegisteredFileProviderDomain(
                    identifier: profile.domainIdentifier,
                    displayName: "Alpha",
                    isDisconnected: false
                ),
            ]
        )
        let coordinator = AppleSyncProfileDomainCoordinator(manager: manager)

        let registered = try await coordinator.registeredProfiles([profile])

        XCTAssertEqual(registered[profile.domainIdentifier]?.displayName, "Alpha")
    }

    func testSyncProfileReconcileContinuesAfterOneProfileFails() async {
        let broken = AppleSyncProfile(id: "broken", displayName: "Broken")
        let healthy = AppleSyncProfile(id: "healthy", displayName: "Healthy")
        let manager = MockFileProviderDomainManager(
            failingAddIdentifiers: [broken.domainIdentifier]
        )
        let coordinator = AppleSyncProfileDomainCoordinator(manager: manager)

        let errors = await coordinator.reconcile([broken, healthy])

        XCTAssertEqual(errors.count, 1)
        XCTAssertTrue(errors[0].contains("Broken"))
        let addedIdentifiers = await manager.recordedAdds().map(\.identifier)
        XCTAssertEqual(addedIdentifiers, [
            broken.domainIdentifier,
            healthy.domainIdentifier,
        ])
    }
}

private actor MockFileProviderDomainManager: AppleFileProviderDomainManaging {
    private var domainsToReturn: [AppleRegisteredFileProviderDomain]
    private let postAddDomains: [AppleRegisteredFileProviderDomain]?
    private let addError: Error?
    private let failingAddIdentifiers: Set<String>
    private var addRequests: [AppleRegisteredFileProviderDomain] = []
    private var lifecycleOperations: [String] = []

    init(
        domainsToReturn: [AppleRegisteredFileProviderDomain] = [],
        addError: Error? = nil,
        postAddDomains: [AppleRegisteredFileProviderDomain]? = nil,
        failingAddIdentifiers: Set<String> = []
    ) {
        self.domainsToReturn = domainsToReturn
        self.addError = addError
        self.postAddDomains = postAddDomains
        self.failingAddIdentifiers = failingAddIdentifiers
    }

    func add(identifier: String, displayName: String) async throws {
        let domain = AppleRegisteredFileProviderDomain(
            identifier: identifier,
            displayName: displayName
        )
        addRequests.append(domain)
        if failingAddIdentifiers.contains(identifier) {
            throw MockDomainError("Configured add failure for \(identifier).")
        }
        if let postAddDomains {
            domainsToReturn = postAddDomains
        } else if addError == nil {
            domainsToReturn.append(domain)
        }

        if let addError {
            throw addError
        }
    }

    func domains() async throws -> [AppleRegisteredFileProviderDomain] {
        domainsToReturn
    }

    func remove(identifier: String, displayName: String) async throws {
        _ = displayName
        lifecycleOperations.append("remove:\(identifier)")
        domainsToReturn.removeAll { $0.identifier == identifier }
    }

    func disconnect(identifier: String, displayName: String, reason: String) async throws {
        _ = displayName
        _ = reason
        lifecycleOperations.append("disconnect:\(identifier)")
    }

    func reconnect(identifier: String, displayName: String) async throws {
        _ = displayName
        lifecycleOperations.append("reconnect:\(identifier)")
    }

    func signalChanges(identifier: String, displayName: String) async throws {
        _ = displayName
        lifecycleOperations.append("signal:\(identifier)")
    }

    func recordedAdds() -> [AppleRegisteredFileProviderDomain] {
        addRequests
    }

    func recordedLifecycleOperations() -> [String] {
        lifecycleOperations
    }
}

private struct MockDomainError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? {
        message
    }
}
