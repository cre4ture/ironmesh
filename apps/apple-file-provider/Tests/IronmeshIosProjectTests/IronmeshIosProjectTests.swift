import AppleCore
import AppleFileProviderShared
import XCTest

final class IronmeshIosProjectTests: XCTestCase {
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
}

private actor MockFileProviderDomainManager: AppleFileProviderDomainManaging {
    private var domainsToReturn: [AppleRegisteredFileProviderDomain]
    private let postAddDomains: [AppleRegisteredFileProviderDomain]?
    private let addError: Error?
    private var addRequests: [AppleRegisteredFileProviderDomain] = []

    init(
        domainsToReturn: [AppleRegisteredFileProviderDomain] = [],
        addError: Error? = nil,
        postAddDomains: [AppleRegisteredFileProviderDomain]? = nil
    ) {
        self.domainsToReturn = domainsToReturn
        self.addError = addError
        self.postAddDomains = postAddDomains
    }

    func add(identifier: String, displayName: String) async throws {
        let domain = AppleRegisteredFileProviderDomain(
            identifier: identifier,
            displayName: displayName
        )
        addRequests.append(domain)
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

    func recordedAdds() -> [AppleRegisteredFileProviderDomain] {
        addRequests
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
