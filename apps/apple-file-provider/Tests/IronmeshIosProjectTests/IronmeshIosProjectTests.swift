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
}
