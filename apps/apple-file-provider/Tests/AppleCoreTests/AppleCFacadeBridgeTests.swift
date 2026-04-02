import Foundation
import XCTest
@testable import AppleCore

final class AppleCFacadeBridgeTests: XCTestCase {
    func testBridgeRequiresConnectionBeforeOperations() {
        let bridge = AppleCFacadeBridge(ffi: MockFFI())

        XCTAssertThrowsError(try bridge.list(path: "", depth: 1)) { error in
            XCTAssertEqual(error as? AppleManualCBridgeError, .notConnected)
        }
    }

    func testBridgeMapsRustListResponseIntoBridgeItems() throws {
        let ffi = MockFFI()
        ffi.listResponseJSON = """
        {
          "prefix": "",
          "depth": 1,
          "entry_count": 2,
          "entries": [
            {
              "path": "docs/",
              "item_id": "dir:path:docs",
              "kind": "directory"
            },
            {
              "path": "docs/readme.txt",
              "item_id": "file:object:obj-123",
              "kind": "file",
              "object_id": "obj-123",
              "preferred_head_version_id": "version-1",
              "size_bytes": 12,
              "modified_at_unix": 1234
            }
          ]
        }
        """

        let bridge = AppleCFacadeBridge(ffi: ffi)
        _ = try bridge.connect(AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080"))
        let items = try bridge.list(path: "docs", depth: 1)

        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(items[0].identifier.serialized, "dir:path:docs")
        XCTAssertEqual(items[0].kind, .directory)
        XCTAssertEqual(items[1].identifier.serialized, "file:object:obj-123")
        XCTAssertEqual(items[1].objectID, "obj-123")
        XCTAssertEqual(items[1].revisionHint, "version-1")
        XCTAssertEqual(items[1].sizeBytes, 12)
        XCTAssertEqual(ffi.lastListPrefix, "docs/")
        XCTAssertEqual(ffi.lastListDepth, 1)
    }

    func testBridgeRejectsObjectIdentifierLookupsUntilRustSupportsThem() throws {
        let bridge = AppleCFacadeBridge(ffi: MockFFI())
        _ = try bridge.connect(AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080"))

        XCTAssertThrowsError(try bridge.metadata(pathOrIdentifier: "file:object:obj-123")) { error in
            XCTAssertEqual(
                error as? AppleManualCBridgeError,
                .unsupportedIdentifier("file:object:obj-123")
            )
        }
    }

    func testBridgeMapsMetadataAndMutationsThroughFFI() throws {
        let ffi = MockFFI()
        ffi.metadataResponseJSON = """
        {
          "key": "docs/readme.txt",
          "item_id": "file:object:obj-123",
          "kind": "file",
          "object_id": "obj-123",
          "version_graph": {
            "preferred_head_version_id": "version-9"
          }
        }
        """
        ffi.putResponseJSON = """
        {
          "item_id": "file:object:obj-123",
          "object_id": "obj-123",
          "version_graph": {
            "preferred_head_version_id": "version-10"
          }
        }
        """
        ffi.fetchResponseData = Data("hello".utf8)

        let bridge = AppleCFacadeBridge(ffi: ffi)
        let session = try bridge.connect(AppleConnectionConfiguration(connectionInput: "http://127.0.0.1:18080"))
        XCTAssertEqual(session.rootPath, "/")

        let metadata = try bridge.metadata(pathOrIdentifier: "docs/readme.txt")
        XCTAssertEqual(metadata?.identifier.serialized, "file:object:obj-123")
        XCTAssertEqual(metadata?.revisionHint, "version-9")

        let upload = try bridge.upload(path: "docs/readme.txt", data: Data("hello".utf8), expectedRevision: nil)
        XCTAssertTrue(upload.accepted)
        XCTAssertEqual(upload.resultingIdentifier, "file:object:obj-123")
        XCTAssertEqual(upload.resultingRevision, "version-10")

        let bytes = try bridge.download(path: "docs/readme.txt", revisionHint: nil)
        XCTAssertEqual(String(decoding: bytes, as: UTF8.self), "hello")

        let move = try bridge.move(from: "docs/readme.txt", to: "docs/guide.txt", expectedRevision: nil)
        XCTAssertTrue(move.accepted)
        XCTAssertEqual(ffi.lastMoveFromPath, "docs/readme.txt")
        XCTAssertEqual(ffi.lastMoveToPath, "docs/guide.txt")

        let delete = try bridge.delete(path: "docs/guide.txt", expectedRevision: nil)
        XCTAssertTrue(delete.accepted)
        XCTAssertEqual(ffi.lastDeletePath, "docs/guide.txt")
    }

    func testMkdirReturnsNonAcceptedPlaceholderUntilDirectoryCreationExists() throws {
        let bridge = AppleCFacadeBridge(ffi: MockFFI())
        let result = try bridge.mkdir(path: "docs/new-folder")

        XCTAssertFalse(result.accepted)
        XCTAssertEqual(result.resultingIdentifier, "dir:path:docs/new-folder")
    }
}

private final class MockFFI: AppleManualCBridgeFFI, @unchecked Sendable {
    var createdConnectionInput: String?
    var lastListPrefix: String?
    var lastListDepth: Int?
    var lastDeletePath: String?
    var lastMoveFromPath: String?
    var lastMoveToPath: String?

    var listResponseJSON = #"{"entries":[]}"#
    var metadataResponseJSON = #"{"key":"","item_id":"dir:root","kind":"directory"}"#
    var putResponseJSON = #"{"item_id":"file:path:test.txt"}"#
    var fetchResponseData = Data()

    func createHandle(
        connectionInput: String,
        serverCAPem: String?,
        clientIdentityJSON: String?
    ) throws -> AppleRustHandle {
        _ = serverCAPem
        _ = clientIdentityJSON
        createdConnectionInput = connectionInput
        return AppleRustHandle(bitPattern: 0x1)!
    }

    func freeHandle(_ handle: AppleRustHandle) {
        _ = handle
    }

    func listJSON(handle: AppleRustHandle, prefix: String?, depth: Int, snapshot: String?) throws -> String {
        _ = handle
        _ = snapshot
        lastListPrefix = prefix
        lastListDepth = depth
        return listResponseJSON
    }

    func metadataJSON(handle: AppleRustHandle, key: String) throws -> String {
        _ = handle
        _ = key
        return metadataResponseJSON
    }

    func fetchBytes(handle: AppleRustHandle, key: String) throws -> Data {
        _ = handle
        _ = key
        return fetchResponseData
    }

    func putBytes(handle: AppleRustHandle, key: String, data: Data) throws -> String {
        _ = handle
        _ = key
        _ = data
        return putResponseJSON
    }

    func deletePath(handle: AppleRustHandle, key: String) throws {
        _ = handle
        lastDeletePath = key
    }

    func movePath(handle: AppleRustHandle, fromPath: String, toPath: String, overwrite: Bool) throws {
        _ = handle
        _ = overwrite
        lastMoveFromPath = fromPath
        lastMoveToPath = toPath
    }
}
