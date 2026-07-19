import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

func truncatedVersionData(_ value: String) -> Data {
    let data = Data(value.utf8)
    if data.count <= 128 {
        return data
    }
    return data.prefix(128)
}

func asNSError(_ error: Error) -> NSError {
    if let nsError = error as NSError? {
        return nsError
    }
    return NSError(
        domain: NSCocoaErrorDomain,
        code: NSXPCConnectionReplyInvalid,
        userInfo: [NSUnderlyingErrorKey: error]
    )
}

func fileProviderError(_ code: NSFileProviderError.Code) -> NSError {
    NSError(domain: NSFileProviderErrorDomain, code: code.rawValue)
}

func unsupportedFeatureError(_ message: String) -> NSError {
    NSError(
        domain: NSCocoaErrorDomain,
        code: NSFeatureUnsupportedError,
        userInfo: [NSLocalizedDescriptionKey: message]
    )
}

func mutationUsageError(_ message: String) -> NSError {
    NSError(
        domain: NSCocoaErrorDomain,
        code: NSXPCConnectionReplyInvalid,
        userInfo: [NSLocalizedDescriptionKey: message]
    )
}

final class UncheckedBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

extension AppleBridgeItem {
    var parentPath: String {
        let normalized = normalizedPath(path)
        guard let slashIndex = normalized.lastIndex(of: "/") else {
            return ""
        }
        return String(normalized[..<slashIndex])
    }
}
