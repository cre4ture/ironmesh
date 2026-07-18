import Foundation
import XCTest
@testable import AppleCore

final class AppleStoreIndexTests: XCTestCase {
    func testStoreIndexDecodesSnakeCaseMediaThumbnailAndGPS() throws {
        let response = try decodeResponse(
            """
            {
              "prefix": "photos",
              "depth": 64,
              "entry_count": 1,
              "total_entry_count": 41,
              "offset": 32,
              "limit": 32,
              "has_more": true,
              "next_cursor": "future-page",
              "media_summary": {
                "ready_count": 1,
                "pending_count": 2,
                "incomplete_count": 3,
                "image_count": 4,
                "video_count": 5,
                "geotagged_count": 6
              },
              "entries": [
                {
                  "path": "photos/cat.jpg",
                  "entry_type": "key",
                  "version": "v1",
                  "content_hash": "hash",
                  "size_bytes": 123,
                  "modified_at_unix": 456,
                  "content_fingerprint": "entry-fingerprint",
                  "future_entry_field": true,
                  "media": {
                    "status": "ready",
                    "content_fingerprint": "media-fingerprint",
                    "media_type": "image",
                    "mime_type": "image/jpeg",
                    "width": 4032,
                    "height": 3024,
                    "orientation": 1,
                    "taken_at_unix": 789,
                    "gps": {"latitude": 47.3769, "longitude": 8.5417},
                    "thumbnail": {
                      "url": "/media/thumbnail?key=photos%2Fcat.jpg",
                      "profile": "grid",
                      "width": 256,
                      "height": 256,
                      "format": "jpeg",
                      "size_bytes": 9876,
                      "future_thumbnail_field": "ignored"
                    },
                    "error": null,
                    "future_media_field": {"ignored": true}
                  }
                }
              ],
              "future_response_field": [1, 2, 3]
            }
            """
        )

        XCTAssertEqual(response.totalEntryCount, 41)
        XCTAssertEqual(response.mediaSummary.geotaggedCount, 6)
        let entry = try XCTUnwrap(response.entries.first)
        XCTAssertEqual(entry.entryType, .key)
        XCTAssertEqual(entry.contentFingerprint, "entry-fingerprint")
        XCTAssertEqual(entry.media?.status, .ready)
        let gps = try XCTUnwrap(entry.media?.gps)
        XCTAssertEqual(gps.latitude, 47.3769, accuracy: 0.0001)
        XCTAssertEqual(gps.longitude, 8.5417, accuracy: 0.0001)
        XCTAssertEqual(entry.media?.thumbnail?.sizeBytes, 9876)
    }

    func testStoreIndexKeepsFutureEntryAndMediaStatesDecodable() throws {
        let response = try decodeResponse(
            """
            {
              "prefix": "",
              "depth": 1,
              "entry_count": 1,
              "total_entry_count": 1,
              "offset": 0,
              "has_more": false,
              "media_summary": {
                "ready_count": 0,
                "pending_count": 0,
                "incomplete_count": 0,
                "image_count": 0,
                "video_count": 0,
                "geotagged_count": 0
              },
              "entries": [
                {
                  "path": "future.asset",
                  "entry_type": "virtual_key",
                  "media": {
                    "status": "processing_v2",
                    "content_fingerprint": "future"
                  }
                }
              ]
            }
            """
        )

        XCTAssertEqual(response.entries.first?.entryType, .unknown("virtual_key"))
        XCTAssertEqual(response.entries.first?.media?.status, .unknown("processing_v2"))
    }

    func testGalleryQueryMapsModeSortAndServerPagination() {
        let allImages = AppleGalleryQuery(
            mode: .allImages,
            currentPath: "ignored/folder",
            sort: .newest
        ).request(offset: 32)
        let currentFolder = AppleGalleryQuery(
            mode: .currentFolder,
            currentPath: "/photos/trips/",
            sort: .path,
            pageSize: 12
        ).request(offset: 24)

        XCTAssertNil(allImages.prefix)
        XCTAssertEqual(allImages.depth, 64)
        XCTAssertEqual(allImages.options.view, .tree)
        XCTAssertEqual(allImages.options.offset, 32)
        XCTAssertEqual(allImages.options.limit, 32)
        XCTAssertEqual(allImages.options.sort, .capturedDescending)
        XCTAssertEqual(allImages.options.mediaFilter, .image)

        XCTAssertEqual(currentFolder.prefix, "photos/trips")
        XCTAssertEqual(currentFolder.depth, 1)
        XCTAssertEqual(currentFolder.options.view, .tree)
        XCTAssertEqual(currentFolder.options.offset, 24)
        XCTAssertEqual(currentFolder.options.limit, 12)
        XCTAssertEqual(currentFolder.options.sort, .pathAscending)
    }

    func testGalleryPaginationAdvancesByServerPageWithoutLoadingWholeCollection() throws {
        var pagination = AppleGalleryPagination()
        let response = try decodeResponse(
            """
            {
              "prefix": "",
              "depth": 64,
              "entry_count": 2,
              "total_entry_count": 65,
              "offset": 32,
              "limit": 32,
              "has_more": true,
              "media_summary": {
                "ready_count": 2,
                "pending_count": 0,
                "incomplete_count": 0,
                "image_count": 2,
                "video_count": 0,
                "geotagged_count": 0
              },
              "entries": [
                {"path": "a.jpg", "entry_type": "key"},
                {"path": "b.jpg", "entry_type": "key"}
              ]
            }
            """
        )

        pagination.record(response)

        XCTAssertEqual(pagination.nextOffset, 34)
        XCTAssertEqual(pagination.totalCount, 65)
        XCTAssertTrue(pagination.hasMore)
    }

    func testGalleryRequestGateRejectsStaleResults() {
        var gate = AppleGalleryRequestGate()
        let first = gate.begin()
        let second = gate.begin()

        XCTAssertFalse(gate.accepts(first))
        XCTAssertTrue(gate.accepts(second))

        gate.invalidate()
        XCTAssertFalse(gate.accepts(second))
    }

    func testGalleryCacheContextRejectsOldConnectionGeneration() {
        var gate = AppleGalleryCacheContextGate()
        let firstConfiguration = AppleConnectionConfiguration(
            connectionInput: "cluster-a.example",
            clientIdentityJSON: #"{"device_id":"a"}"#
        )
        let secondConfiguration = AppleConnectionConfiguration(
            connectionInput: "cluster-b.example",
            clientIdentityJSON: #"{"device_id":"b"}"#
        )

        let first = gate.prepare(for: firstConfiguration)
        let repeated = gate.prepare(for: firstConfiguration)
        let second = gate.prepare(for: secondConfiguration)

        XCTAssertTrue(first.contextChanged)
        XCTAssertFalse(repeated.contextChanged)
        XCTAssertEqual(repeated.generation, first.generation)
        XCTAssertTrue(second.contextChanged)
        XCTAssertNil(gate.generation(for: firstConfiguration))
        XCTAssertEqual(gate.generation(for: secondConfiguration), second.generation)
        XCTAssertFalse(gate.accepts(generation: first.generation, configuration: firstConfiguration))
        XCTAssertTrue(gate.accepts(generation: second.generation, configuration: secondConfiguration))
    }

    func testFullImageCacheIdentityUsesFingerprintAndMetadataFallbacks() throws {
        let fingerprinted = try decodeEntry(
            """
            {
              "path": "photos/cat.jpg",
              "entry_type": "key",
              "content_fingerprint": "fingerprint-v2",
              "modified_at_unix": 10,
              "size_bytes": 20
            }
            """
        )
        let metadataOnly = try decodeEntry(
            """
            {
              "path": "photos/cat.jpg",
              "entry_type": "key",
              "modified_at_unix": 11,
              "size_bytes": 21
            }
            """
        )

        XCTAssertEqual(
            AppleGalleryCacheIdentity.fullImageKey(for: fingerprinted),
            "photos/cat.jpg\nfingerprint-v2"
        )
        XCTAssertEqual(
            AppleGalleryCacheIdentity.fullImageKey(for: metadataOnly),
            "photos/cat.jpg\nmodified=11;size=21"
        )
    }

    func testThumbnailPathUsesSafeAdvertisedRelativeURLAndEncodedFallback() throws {
        let advertised = try decodeEntry(
            """
            {
              "path": "photos/cat.jpg",
              "entry_type": "key",
              "media": {
                "status": "ready",
                "content_fingerprint": "fingerprint",
                "thumbnail": {
                  "url": "/media/thumbnail?key=photos%2Fcat.jpg&version=v1",
                  "profile": "grid",
                  "width": 256,
                  "height": 256,
                  "format": "jpeg",
                  "size_bytes": 100
                }
              }
            }
            """
        )
        let external = try decodeEntry(
            """
            {
              "path": "photos/Cat one+?.jpg",
              "entry_type": "key",
              "media": {
                "status": "pending",
                "content_fingerprint": "fingerprint",
                "thumbnail": {
                  "url": "https://untrusted.example/thumbnail",
                  "profile": "grid",
                  "width": 256,
                  "height": 256,
                  "format": "jpeg",
                  "size_bytes": 0
                }
              }
            }
            """
        )

        XCTAssertEqual(
            AppleGalleryThumbnailPath.relativePath(for: advertised),
            "/media/thumbnail?key=photos%2Fcat.jpg&version=v1"
        )
        XCTAssertEqual(
            AppleGalleryThumbnailPath.relativePath(for: external),
            "/media/thumbnail?key=photos%2FCat%20one%2B%3F.jpg"
        )
    }

    private func decodeResponse(_ json: String) throws -> AppleStoreIndexResponse {
        try JSONDecoder().decode(AppleStoreIndexResponse.self, from: Data(json.utf8))
    }

    private func decodeEntry(_ json: String) throws -> AppleStoreIndexEntry {
        try JSONDecoder().decode(AppleStoreIndexEntry.self, from: Data(json.utf8))
    }
}
