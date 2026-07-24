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
            "preferred_head_version_id": "version-10",
            "head_version_ids": ["version-10"]
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

        let upload = try bridge.upload(path: "docs/readme.txt", data: Data("hello".utf8), expectedRevision: "version-9")
        XCTAssertTrue(upload.accepted)
        XCTAssertEqual(upload.resultingIdentifier, "file:object:obj-123")
        XCTAssertEqual(upload.resultingRevision, "version-10")
        XCTAssertEqual(ffi.lastPutExpectedRevision, "version-9")

        let bytes = try bridge.download(path: "docs/readme.txt", revisionHint: nil)
        XCTAssertEqual(String(decoding: bytes, as: UTF8.self), "hello")

        let move = try bridge.move(from: "docs/readme.txt", to: "docs/guide.txt", expectedRevision: "version-10")
        XCTAssertTrue(move.accepted)
        XCTAssertEqual(ffi.lastMoveFromPath, "docs/readme.txt")
        XCTAssertEqual(ffi.lastMoveToPath, "docs/guide.txt")
        XCTAssertEqual(ffi.lastMoveExpectedRevision, "version-10")

        let delete = try bridge.delete(path: "docs/guide.txt", expectedRevision: "version-10")
        XCTAssertTrue(delete.accepted)
        XCTAssertEqual(ffi.lastDeletePath, "docs/guide.txt")
        XCTAssertEqual(ffi.lastDeleteExpectedRevision, "version-10")
    }

    func testDeletePreservesDirectoryMarkerForRecursiveDeletes() throws {
        let ffi = MockFFI()
        let bridge = AppleCFacadeBridge(ffi: ffi)
        _ = try bridge.connect(AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080"))

        let delete = try bridge.delete(path: "docs/archive/", expectedRevision: nil)

        XCTAssertTrue(delete.accepted)
        XCTAssertEqual(ffi.lastDeletePath, "docs/archive/")
    }

    func testUploadReportsDivergentHeadsForVisibleConflictRecovery() throws {
        let ffi = MockFFI()
        ffi.putResponseJSON = """
        {
          "item_id": "file:object:obj-123",
          "version_graph": {
            "preferred_head_version_id": "local-head",
            "head_version_ids": ["remote-head", "local-head"]
          }
        }
        """
        let bridge = AppleCFacadeBridge(ffi: ffi)
        _ = try bridge.connect(AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080"))

        let result = try bridge.upload(
            path: "docs/readme.txt",
            data: Data("local".utf8),
            expectedRevision: "base-head"
        )

        XCTAssertEqual(result.conflictingRevision, "local-head,remote-head")
        XCTAssertEqual(ffi.lastPutExpectedRevision, "base-head")
    }

    func testMkdirReturnsNonAcceptedPlaceholderUntilDirectoryCreationExists() throws {
        let bridge = AppleCFacadeBridge(ffi: MockFFI())
        let result = try bridge.mkdir(path: "docs/new-folder")

        XCTAssertFalse(result.accepted)
        XCTAssertEqual(result.resultingIdentifier, "dir:path:docs/new-folder")
    }

    func testConnectionRouteSnapshotForwardsRefreshChoice() throws {
        let ffi = MockFFI()
        ffi.routeSnapshotResponseJSON = #"{"ranked_indices":[0],"endpoints":[]}"#
        let bridge = AppleCFacadeBridge(ffi: ffi)
        _ = try bridge.connect(AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080"))

        let response = try bridge.connectionRouteSnapshotJSON(refresh: true)

        XCTAssertEqual(response, ffi.routeSnapshotResponseJSON)
        XCTAssertEqual(ffi.lastRouteSnapshotRefresh, true)
    }

    func testTitleLatencyMonitorForwardsConfiguredPeriod() throws {
        let ffi = MockFFI()
        ffi.titleLatencyStatusResponseJSON = #"{"state":"pending","connection_type":"direct"}"#
        let bridge = AppleCFacadeBridge(ffi: ffi)
        _ = try bridge.connect(AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080"))

        let response = try bridge.configureTitleLatencyMonitorJSON(
            settings: AppleTitleLatencyMonitorSettings(enabled: true, periodSeconds: 45)
        )

        XCTAssertEqual(response, ffi.titleLatencyStatusResponseJSON)
        XCTAssertEqual(ffi.lastTitleLatencyEnabled, true)
        XCTAssertEqual(ffi.lastTitleLatencyPeriodSeconds, 45)
    }

    func testBridgeMapsStoreIndexOptionsAndRelativeBytesThroughFFI() throws {
        let ffi = MockFFI()
        ffi.storeIndexResponseJSON = """
        {
          "prefix": "photos",
          "depth": 1,
          "entry_count": 1,
          "total_entry_count": 33,
          "offset": 32,
          "limit": 32,
          "has_more": false,
          "next_cursor": null,
          "media_summary": {
            "ready_count": 1,
            "pending_count": 0,
            "incomplete_count": 0,
            "image_count": 1,
            "video_count": 0,
            "geotagged_count": 0
          },
          "entries": [
            {
              "path": "photos/cat.jpg",
              "entry_type": "key",
              "media": {
                "status": "ready",
                "content_fingerprint": "fingerprint",
                "media_type": "image"
              }
            }
          ]
        }
        """
        ffi.relativeResponseData = Data("thumbnail".utf8)

        let bridge = AppleCFacadeBridge(ffi: ffi)
        _ = try bridge.connect(AppleConnectionConfiguration(connectionInput: "127.0.0.1:18080"))
        let response = try bridge.storeIndex(
            AppleStoreIndexRequest(
                prefix: "photos",
                depth: 1,
                options: AppleStoreIndexRequestOptions(
                    offset: 32,
                    limit: 32,
                    sort: .capturedDescending,
                    mediaFilter: .image
                )
            )
        )
        let thumbnail = try bridge.fetchRelativeBytes(path: "/media/thumbnail?key=photos%2Fcat.jpg")

        XCTAssertEqual(response.totalEntryCount, 33)
        XCTAssertEqual(response.entries.first?.entryType, .key)
        XCTAssertEqual(ffi.lastStoreIndexPrefix, "photos")
        XCTAssertEqual(ffi.lastStoreIndexOffset, 32)
        XCTAssertEqual(ffi.lastStoreIndexLimit, 32)
        XCTAssertEqual(ffi.lastStoreIndexSort, "captured_desc")
        XCTAssertEqual(ffi.lastStoreIndexMediaFilter, "image")
        XCTAssertEqual(ffi.lastRelativePath, "/media/thumbnail?key=photos%2Fcat.jpg")
        XCTAssertEqual(String(decoding: thumbnail, as: UTF8.self), "thumbnail")
    }
}

private final class MockFFI: AppleManualCBridgeFFI, @unchecked Sendable {
    var createdConnectionInput: String?
    var lastListPrefix: String?
    var lastListDepth: Int?
    var lastDeletePath: String?
    var lastDeleteExpectedRevision: String?
    var lastPutExpectedRevision: String?
    var lastMoveFromPath: String?
    var lastMoveToPath: String?
    var lastMoveExpectedRevision: String?
    var lastStoreIndexPrefix: String?
    var lastStoreIndexOffset: Int?
    var lastStoreIndexLimit: Int?
    var lastStoreIndexSort: String?
    var lastStoreIndexMediaFilter: String?
    var lastRelativePath: String?

    var listResponseJSON = #"{"entries":[]}"#
    var storeIndexResponseJSON = #"{"prefix":"","depth":1,"entry_count":0,"total_entry_count":0,"offset":0,"has_more":false,"media_summary":{"ready_count":0,"pending_count":0,"incomplete_count":0,"image_count":0,"video_count":0,"geotagged_count":0},"entries":[]}"#
    var metadataResponseJSON = #"{"key":"","item_id":"dir:root","kind":"directory"}"#
    var putResponseJSON = #"{"item_id":"file:path:test.txt"}"#
    var fetchResponseData = Data()
    var relativeResponseData = Data()
    var diagnosticsResponseJSON = #"{"endpoints":[]}"#
    var routeSnapshotResponseJSON = #"{"ranked_indices":[],"endpoints":[]}"#
    var webUIURL = #"{"url":"http://127.0.0.1:4100/","authorization":"test-session"}"#
    var lastRouteSnapshotRefresh: Bool?
    var lastTitleLatencyEnabled: Bool?
    var lastTitleLatencyPeriodSeconds: UInt64?
    var titleLatencyStatusResponseJSON = #"{"state":"disabled","connection_type":"unknown"}"#

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

    func startWebUi(
        connectionInput: String,
        serverCAPem: String?,
        clientIdentityJSON: String?
    ) throws -> String {
        _ = connectionInput
        _ = serverCAPem
        _ = clientIdentityJSON
        return #"{"url":"http://127.0.0.1:3000/","authorization":"test-session"}"#
    }

    func stopWebUi() throws {}

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

    func storeIndexJSON(
        handle: AppleRustHandle,
        prefix: String?,
        depth: Int,
        snapshot: String?,
        view: String?,
        offset: Int?,
        limit: Int?,
        sort: String?,
        mediaFilter: String?
    ) throws -> String {
        _ = handle
        _ = depth
        _ = snapshot
        _ = view
        lastStoreIndexPrefix = prefix
        lastStoreIndexOffset = offset
        lastStoreIndexLimit = limit
        lastStoreIndexSort = sort
        lastStoreIndexMediaFilter = mediaFilter
        return storeIndexResponseJSON
    }

    func fetchBytes(handle: AppleRustHandle, key: String) throws -> Data {
        _ = handle
        _ = key
        return fetchResponseData
    }

    func fetchRelativeBytes(handle: AppleRustHandle, path: String) throws -> Data {
        _ = handle
        lastRelativePath = path
        return relativeResponseData
    }

    func putBytes(
        handle: AppleRustHandle,
        key: String,
        data: Data,
        expectedRevision: String?
    ) throws -> String {
        _ = handle
        _ = key
        _ = data
        lastPutExpectedRevision = expectedRevision
        return putResponseJSON
    }

    func deletePath(
        handle: AppleRustHandle,
        key: String,
        expectedRevision: String?
    ) throws -> String {
        _ = handle
        lastDeletePath = key
        lastDeleteExpectedRevision = expectedRevision
        return #"{"version_graph":null}"#
    }

    func movePath(
        handle: AppleRustHandle,
        fromPath: String,
        toPath: String,
        overwrite: Bool,
        expectedRevision: String?
    ) throws {
        _ = handle
        _ = overwrite
        lastMoveFromPath = fromPath
        lastMoveToPath = toPath
        lastMoveExpectedRevision = expectedRevision
    }

    func connectionDiagnosticsJSON(handle: AppleRustHandle) throws -> String {
        _ = handle
        return diagnosticsResponseJSON
    }

    func connectionRouteSnapshotJSON(handle: AppleRustHandle, refresh: Bool) throws -> String {
        _ = handle
        lastRouteSnapshotRefresh = refresh
        return routeSnapshotResponseJSON
    }

    func configureTitleLatencyMonitorJSON(
        handle: AppleRustHandle,
        enabled: Bool,
        periodSeconds: UInt64
    ) throws -> String {
        _ = handle
        lastTitleLatencyEnabled = enabled
        lastTitleLatencyPeriodSeconds = periodSeconds
        return titleLatencyStatusResponseJSON
    }

    func titleLatencyStatusJSON(handle: AppleRustHandle) throws -> String {
        _ = handle
        return titleLatencyStatusResponseJSON
    }

    func startWebUI(
        connectionInput: String,
        serverCAPem: String?,
        clientIdentityJSON: String?
    ) throws -> String {
        _ = connectionInput
        _ = serverCAPem
        _ = clientIdentityJSON
        return webUIURL
    }

    func stopWebUI() throws {}
}
