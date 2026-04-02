import AppleCore
import Foundation

struct IronmeshRustFFIError: LocalizedError {
    let message: String

    var errorDescription: String? {
        message
    }
}

final class IronmeshRustFFIAdapter: AppleManualCBridgeFFI, @unchecked Sendable {
    func createHandle(
        connectionInput: String,
        serverCAPem: String?,
        clientIdentityJSON: String?
    ) throws -> AppleRustHandle {
        var errorPointer: UnsafeMutablePointer<CChar>?
        let handle = withOptionalCString(connectionInput) { connectionPointer in
            withOptionalCString(serverCAPem) { serverPointer in
                withOptionalCString(clientIdentityJSON) { identityPointer in
                    ironmesh_ios_facade_create(
                        connectionPointer,
                        serverPointer,
                        identityPointer,
                        &errorPointer
                    )
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

    func putBytes(handle: AppleRustHandle, key: String, data: Data) throws -> String {
        var jsonPointer: UnsafeMutablePointer<CChar>?
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(key) { keyPointer in
            return data.withUnsafeBytes { rawBuffer in
                let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress
                return ironmesh_ios_facade_put_bytes(
                    handle,
                    keyPointer,
                    baseAddress,
                    numericCast(data.count),
                    &jsonPointer,
                    &errorPointer
                )
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
        guard let jsonPointer else {
            throw IronmeshRustFFIError(message: "Rust bridge returned no put JSON.")
        }
        return consumeString(jsonPointer)
    }

    func deletePath(handle: AppleRustHandle, key: String) throws {
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(key) { keyPointer in
            ironmesh_ios_facade_delete_path(handle, keyPointer, &errorPointer)
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
    }

    func movePath(handle: AppleRustHandle, fromPath: String, toPath: String, overwrite: Bool) throws {
        var errorPointer: UnsafeMutablePointer<CChar>?
        let status = withOptionalCString(fromPath) { sourcePointer in
            withOptionalCString(toPath) { destinationPointer in
                ironmesh_ios_facade_move_path(
                    handle,
                    sourcePointer,
                    destinationPointer,
                    overwrite ? 1 : 0,
                    &errorPointer
                )
            }
        }

        try throwIfNeeded(status: status, errorPointer: errorPointer)
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
