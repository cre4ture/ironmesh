import XCTest
@testable import AppleCore

final class AppleCoreTests: XCTestCase {
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
}
