import Foundation
import Security

public protocol AppleSecretStore: Sendable {
    func load() throws -> String?
    func save(_ secret: String) throws
    func clear() throws
}

public struct AppleKeychainSecretStore: AppleSecretStore, Sendable {
    public static let defaultService = "dev.ironmesh.apple.client-identity"
    public static let defaultAccount = "clientIdentityJSON"

    private let service: String
    private let account: String
    let accessGroup: String?

    public init(
        service: String = defaultService,
        account: String = defaultAccount,
        accessGroup: String? = nil
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup?.nilIfBlank
    }

    public func load() throws -> String? {
        var query = baseQuery
        query[kSecMatchLimit] = kSecMatchLimitOne
        query[kSecReturnData] = kCFBooleanTrue

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data,
                  let secret = String(data: data, encoding: .utf8)
            else {
                throw AppleKeychainSecretStoreError.invalidStoredValue
            }
            return secret.nilIfBlank
        case errSecItemNotFound:
            return nil
        default:
            throw AppleKeychainSecretStoreError.operationFailed(
                operation: "load",
                status: status
            )
        }
    }

    public func save(_ secret: String) throws {
        let value = Data(secret.utf8)
        let updateAttributes: [CFString: Any] = [
            kSecValueData: value,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(
            baseQuery as CFDictionary,
            updateAttributes as CFDictionary
        )

        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var attributes = baseQuery
            attributes[kSecValueData] = value
            attributes[kSecAttrAccessible] =
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let addStatus = SecItemAdd(attributes as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw AppleKeychainSecretStoreError.operationFailed(
                    operation: "save",
                    status: addStatus
                )
            }
        default:
            throw AppleKeychainSecretStoreError.operationFailed(
                operation: "save",
                status: updateStatus
            )
        }
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AppleKeychainSecretStoreError.operationFailed(
                operation: "clear",
                status: status
            )
        }
    }

    private var baseQuery: [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
            #if os(macOS)
            // macOS applies iOS-style access groups to Data Protection Keychain items.
            query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
            #endif
        }
        return query
    }
}

public enum AppleKeychainSecretStoreError: Error, Equatable, LocalizedError, Sendable {
    case invalidStoredValue
    case operationFailed(operation: String, status: OSStatus)

    public var errorDescription: String? {
        switch self {
        case .invalidStoredValue:
            return "The stored client identity is not valid UTF-8."
        case .operationFailed(let operation, let status):
            let statusDescription = SecCopyErrorMessageString(status, nil) as String?
            let detail = statusDescription ?? "OSStatus \(status)"
            let prefix = "Could not \(operation) the client identity in the Keychain: "
            return prefix + detail
        }
    }
}
