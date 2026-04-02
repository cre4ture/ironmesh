import XCTest
@testable import AppleFileProviderShared

final class AppleFileProviderSharedTests: XCTestCase {
    func testRootIdentifierSerializesAndParses() {
        let identifier = AppleFileProviderItemIdentifier.root
        XCTAssertEqual(identifier.serialized, "dir:root")
        XCTAssertEqual(AppleFileProviderItemIdentifier(serialized: "dir:root"), identifier)
        XCTAssertEqual(AppleFileProviderItemIdentifier(serialized: "root"), identifier)
        XCTAssertEqual(identifier.directoryPath, "")
    }

    func testFileIdentifierUsesDurableObjectID() {
        let identifier = AppleFileProviderItemIdentifier.file(objectID: "obj-123")
        XCTAssertEqual(identifier.serialized, "file:object:obj-123")
        XCTAssertEqual(
            AppleFileProviderItemIdentifier(serialized: "file:object:obj-123"),
            identifier
        )
        XCTAssertEqual(identifier.fileObjectID, "obj-123")
    }

    func testTemporaryDirectoryIdentifierUsesPathDerivedIdentifier() {
        let identifier = AppleFileProviderItemIdentifier.directory(path: "\\docs\\nested\\")
        XCTAssertEqual(identifier.serialized, "dir:path:docs/nested")
        XCTAssertEqual(identifier.directoryPath, "docs/nested")
        XCTAssertEqual(
            AppleFileProviderItemIdentifier(serialized: "dir:path:docs/nested"),
            identifier
        )
    }

    func testFileItemFallsBackToTemporaryIdentifierWhenObjectIDMissing() {
        let item = AppleFileProviderItem.file(
            path: "docs/readme.txt",
            objectID: nil,
            revisionHint: "v1"
        )

        XCTAssertEqual(item.identifier.serialized, "file:path:docs/readme.txt")
        XCTAssertEqual(item.identifier.temporaryFilePath, "docs/readme.txt")
        XCTAssertFalse(item.isDurable)
        XCTAssertEqual(item.revisionHint, "v1")
    }

    func testDirectoryItemUsesPathDerivedIdentifier() {
        let item = AppleFileProviderItem.directory(path: "docs/nested")

        XCTAssertEqual(item.identifier.serialized, "dir:path:docs/nested")
        XCTAssertEqual(item.displayName, "nested")
        XCTAssertEqual(item.kind, .directory)
    }
}
