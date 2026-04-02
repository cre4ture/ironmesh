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
}
