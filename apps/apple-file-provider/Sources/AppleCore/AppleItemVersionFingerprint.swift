import CryptoKit
import Foundation

public enum AppleItemVersionFingerprint {
    public static func metadataVersion(for item: AppleBridgeItem) -> Data {
        var payload = Data("ironmesh-item-metadata-v1".utf8)
        append(item.identifier.serialized, to: &payload)
        append(normalizedPath(item.path), to: &payload)
        append(item.displayName, to: &payload)
        append(item.kind.rawValue, to: &payload)
        append(item.sizeBytes, to: &payload)
        append(item.modifiedAtUnix, to: &payload)
        return Data(SHA256.hash(data: payload))
    }

    private static func append(_ value: String, to payload: inout Data) {
        let bytes = Data(value.utf8)
        var byteCount = UInt64(bytes.count).bigEndian
        withUnsafeBytes(of: &byteCount) { payload.append(contentsOf: $0) }
        payload.append(bytes)
    }

    private static func append(_ value: Int64?, to payload: inout Data) {
        guard var value = value?.bigEndian else {
            payload.append(0)
            return
        }
        payload.append(1)
        withUnsafeBytes(of: &value) { payload.append(contentsOf: $0) }
    }
}
