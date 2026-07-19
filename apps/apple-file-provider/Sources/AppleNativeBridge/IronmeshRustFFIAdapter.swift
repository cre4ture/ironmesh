import AppleCore
import Foundation

struct IronmeshRustFFIError: LocalizedError {
    let message: String

    var errorDescription: String? {
        message
    }
}

final class IronmeshRustFFIAdapter: AppleManualCBridgeFFI, AppleBootstrapEnroller, @unchecked Sendable {
    private let connectionName: String?

    init(connectionName: String? = "ios file provider") {
        self.connectionName = normalizedOptionalString(connectionName)
    }

    func createHandle(
        connectionInput: String,
        serverCAPem: String?,
        clientIdentityJSON: String?
    ) throws -> AppleRustHandle {
        var errorPointer: UnsafeMutablePointer<CChar>?
        let handle = withOptionalCString(connectionInput) { connectionPointer in
            withOptionalCString(serverCAPem) { serverPointer in
                withOptionalCString(clientIdentityJSON) { identityPointer in
                    withOptionalCString(connectionName) { connectionNamePointer in
                        ironmesh_ios_facade_create_named(
                            connectionPointer,
                            serverPointer,
                            identityPointer,
                            connectionNamePointer,
                            &errorPointer
                        )
                    }
                }
            }
        }

        try throwIfNeeded(status: handle == nil ? 1 : 0, errorPointer: errorPointer)
        guard let handle else {
            throw IronmeshRustFFIError(message: "Rust bridge returned a null handle without an error.")
        }
        return handle
    }

    func freeHandle(_ handle: AppleRustHandle) {
        ironmesh_ios_facade_free(handle)
    }

    func startWebUi(
        connectionInput: String,
        serverCAPem: String?,
        clientIdentityJSON: String?
    ) throws -> String {
        var urlPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(connectionInput) { connectionPointer in
            withOptionalCString(serverCAPem) { serverPointer in
                withOptionalCString(clientIdentityJSON) { identityPointer in
                    ironmesh_ios_facade_start_web_ui(
                        connectionPointer,
                        serverPointer,
                        identityPointer,
                        &urlPointer,
                        &errorPointer
                    )
                }
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let urlPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no Web UI URL.")
        }
        return consumeString(urlPointer)
    }

    func stopWebUi() throws {
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = ironmesh_ios_facade_stop_web_ui(&errorPointer)
        try throwIfNeeded(status: status, errorPointer: errorPointer)
    }

    func listJSON(handle: AppleRustHandle, prefix: String?, depth: Int, snapshot: String?) throws -> String {
        var jsonPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(prefix) { prefixPointer in
            withOptionalCString(snapshot) { snapshotPointer in
                ironmesh_ios_facade_list_json(
                    handle,
                    prefixPointer,
                    numericCast(max(depth, 0)),
                    snapshotPointer,
                    &jsonPointer,
                    &errorPointer
                )
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let jsonPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no list JSON.")
        }
        return consumeString(jsonPointer)
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
        var jsonPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(prefix) { prefixPointer in
            withOptionalCString(snapshot) { snapshotPointer in
                withOptionalCString(view) { viewPointer in
                    withOptionalCString(sort) { sortPointer in
                        withOptionalCString(mediaFilter) { mediaFilterPointer in
                            ironmesh_ios_facade_store_index_with_options_json(
                                handle,
                                prefixPointer,
                                numericCast(max(depth, 1)),
                                snapshotPointer,
                                viewPointer,
                                offset ?? -1,
                                limit ?? -1,
                                sortPointer,
                                mediaFilterPointer,
                                &jsonPointer,
                                &errorPointer
                            )
                        }
                    }
                }
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let jsonPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no store index JSON.")
        }
        return consumeString(jsonPointer)
    }

    func metadataJSON(handle: AppleRustHandle, key: String) throws -> String {
        var jsonPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(key) { keyPointer in
            ironmesh_ios_facade_metadata_json(handle, keyPointer, &jsonPointer, &errorPointer)
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let jsonPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no metadata JSON.")
        }
        return consumeString(jsonPointer)
    }

    func fetchBytes(handle: AppleRustHandle, key: String) throws -> Data {
        var bytes = IronmeshIosBytes(data: nil, len: 0, capacity: 0)
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(key) { keyPointer in
            ironmesh_ios_facade_fetch_bytes(handle, keyPointer, &bytes, &errorPointer)
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let dataPointer = bytes.data else {
            return Data()
        }

        let data = Data(bytes: dataPointer, count: Int(bytes.len))
        ironmesh_ios_bytes_free(bytes)
        return data
    }

    func fetchRelativeBytes(handle: AppleRustHandle, path: String) throws -> Data {
        var bytes = IronmeshIosBytes(data: nil, len: 0, capacity: 0)
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(path) { pathPointer in
            ironmesh_ios_facade_fetch_relative_bytes(handle, pathPointer, &bytes, &errorPointer)
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let dataPointer = bytes.data else {
            return Data()
        }

        let data = Data(bytes: dataPointer, count: Int(bytes.len))
        ironmesh_ios_bytes_free(bytes)
        return data
    }

    func putBytes(
        handle: AppleRustHandle,
        key: String,
        data: Data,
        expectedRevision: String?
    ) throws -> String {
        var jsonPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(key) { keyPointer in
            withOptionalCString(expectedRevision) { revisionPointer in
                data.withUnsafeBytes { rawBuffer in
                    let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress
                    return ironmesh_ios_facade_put_bytes_with_expected_revision(
                        handle,
                        keyPointer,
                        baseAddress,
                        numericCast(data.count),
                        revisionPointer,
                        &jsonPointer,
                        &errorPointer
                    )
                }
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let jsonPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no put JSON.")
        }
        return consumeString(jsonPointer)
    }

    func deletePath(
        handle: AppleRustHandle,
        key: String,
        expectedRevision: String?
    ) throws -> String {
        var jsonPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(key) { keyPointer in
            withOptionalCString(expectedRevision) { revisionPointer in
                ironmesh_ios_facade_delete_path_with_expected_revision(
                    handle,
                    keyPointer,
                    revisionPointer,
                    &jsonPointer,
                    &errorPointer
                )
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let jsonPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no delete JSON.")
        }
        return consumeString(jsonPointer)
    }

    func movePath(
        handle: AppleRustHandle,
        fromPath: String,
        toPath: String,
        overwrite: Bool,
        expectedRevision: String?
    ) throws {
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(fromPath) { sourcePointer in
            withOptionalCString(toPath) { destinationPointer in
                withOptionalCString(expectedRevision) { revisionPointer in
                    ironmesh_ios_facade_move_path_with_expected_revision(
                        handle,
                        sourcePointer,
                        destinationPointer,
                        overwrite ? 1 : 0,
                        revisionPointer,
                        &errorPointer
                    )
                }
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
    }

    func connectionDiagnosticsJSON(handle: AppleRustHandle) throws -> String {
        var jsonPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = ironmesh_ios_facade_connection_diagnostics_json(
            handle,
            &jsonPointer,
            &errorPointer
        )

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let jsonPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no diagnostics JSON.")
        }
        return consumeString(jsonPointer)
    }

    func connectionRouteSnapshotJSON(handle: AppleRustHandle, refresh: Bool) throws -> String {
        var jsonPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = ironmesh_ios_facade_connection_route_snapshot_json(
            handle,
            refresh ? 1 : 0,
            &jsonPointer,
            &errorPointer
        )

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let jsonPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no connection paths JSON.")
        }
        return consumeString(jsonPointer)
    }

    func startWebUI(
        connectionInput: String,
        serverCAPem: String?,
        clientIdentityJSON: String?
    ) throws -> String {
        var urlPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(connectionInput) { connectionPointer in
            withOptionalCString(serverCAPem) { serverPointer in
                withOptionalCString(clientIdentityJSON) { identityPointer in
                    ironmesh_ios_facade_start_web_ui(
                        connectionPointer,
                        serverPointer,
                        identityPointer,
                        &urlPointer,
                        &errorPointer
                    )
                }
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let urlPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no web UI URL.")
        }
        return consumeString(urlPointer)
    }

    func stopWebUI() throws {
        try stopWebUi()
    }

    func enrollConnectionInput(
        _ connectionInput: String,
        deviceID: String?,
        label: String?
    ) throws -> AppleBootstrapEnrollmentResult {
        var jsonPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(connectionInput) { connectionPointer in
            withOptionalCString(deviceID) { deviceIDPointer in
                withOptionalCString(label) { labelPointer in
                    ironmesh_ios_facade_enroll_with_bootstrap(
                        connectionPointer,
                        deviceIDPointer,
                        labelPointer,
                        &jsonPointer,
                        &errorPointer
                    )
                }
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let jsonPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no enrollment JSON.")
        }

        let json = consumeString(jsonPointer)
        let data = Data(json.utf8)
        do {
            return try JSONDecoder().decode(AppleBootstrapEnrollmentResult.self, from: data)
        } catch {
            throw IronmeshRustFFIError(message: "Failed to decode enrollment JSON: \(error.localizedDescription)")
        }
    }
}

private func throwIfNeeded(status: Int32, errorPointer: UnsafeMutablePointer<CChar>?) throws {
    if let errorPointer {
        let message = consumeString(errorPointer)
        throw IronmeshRustFFIError(message: message)
    }

    guard status == 0 else {
        throw IronmeshRustFFIError(message: "Rust bridge operation failed without an error string.")
    }
}

private func consumeString(_ pointer: UnsafeMutablePointer<CChar>) -> String {
    let value = String(cString: pointer)
    ironmesh_ios_string_free(pointer)
    return value
}

private func withOptionalCString<Result>(
    _ value: String?,
    _ body: (UnsafePointer<CChar>?) -> Result
) -> Result {
    guard let value else {
        return body(nil)
    }
    return value.withCString { body($0) }
}

private func normalizedOptionalString(_ value: String?) -> String? {
    guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
        return nil
    }
    return value
}
