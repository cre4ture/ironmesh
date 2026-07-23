import Foundation

public struct AppleStoredConnectionState: Sendable, Codable, Equatable {
    public var connectionInput: String?
    public var serverCAPem: String?
    public var clientIdentityJSON: String?
    public var deviceID: String?
    public var deviceLabel: String?
    public var bootstrapInputDraft: String?

    public init(
        connectionInput: String? = nil,
        serverCAPem: String? = nil,
        clientIdentityJSON: String? = nil,
        deviceID: String? = nil,
        deviceLabel: String? = nil,
        bootstrapInputDraft: String? = nil
    ) {
        self.connectionInput = connectionInput?.nilIfBlank
        self.serverCAPem = serverCAPem?.nilIfBlank
        self.clientIdentityJSON = clientIdentityJSON?.nilIfBlank
        self.deviceID = deviceID?.nilIfBlank
        self.deviceLabel = deviceLabel?.nilIfBlank
        self.bootstrapInputDraft = bootstrapInputDraft?.nilIfBlank
    }

    public func effectiveConfiguration(
        fallback: AppleConnectionConfiguration
    ) -> AppleConnectionConfiguration {
        AppleConnectionConfiguration(
            connectionInput: connectionInput?.nilIfBlank ?? fallback.connectionInput,
            serverCAPem: serverCAPem?.nilIfBlank ?? fallback.serverCAPem,
            clientIdentityJSON: clientIdentityJSON?.nilIfBlank ?? fallback.clientIdentityJSON
        )
    }

    public func clearingEnrollment() -> AppleStoredConnectionState {
        AppleStoredConnectionState(
            connectionInput: connectionInput,
            serverCAPem: serverCAPem,
            clientIdentityJSON: nil,
            deviceID: nil,
            deviceLabel: nil,
            bootstrapInputDraft: bootstrapInputDraft
        )
    }

    public func withBootstrapDraft(_ draft: String?) -> AppleStoredConnectionState {
        AppleStoredConnectionState(
            connectionInput: connectionInput,
            serverCAPem: serverCAPem,
            clientIdentityJSON: clientIdentityJSON,
            deviceID: deviceID,
            deviceLabel: deviceLabel,
            bootstrapInputDraft: draft
        )
    }
}

/// The Rust-owned persistence contract returned by device enrollment.
///
/// Swift only stores this already-normalized connection target and moves the identity JSON into
/// the Keychain. It must not derive a reconnect target from the claim or reconstruct identity
/// JSON from individual key fields.
public struct AppleEnrolledConnection: Sendable, Codable, Equatable {
    public var clusterID: String
    public var connectionInput: String
    public var deviceID: String
    public var deviceLabel: String?
    public var serverCAPem: String?
    public var clientIdentityJSON: String

    public init(
        clusterID: String,
        connectionInput: String,
        deviceID: String,
        deviceLabel: String? = nil,
        serverCAPem: String? = nil,
        clientIdentityJSON: String
    ) {
        self.clusterID = clusterID
        self.connectionInput = connectionInput.nilIfBlank ?? ""
        self.deviceID = deviceID
        self.deviceLabel = deviceLabel?.nilIfBlank
        self.serverCAPem = serverCAPem?.nilIfBlank
        self.clientIdentityJSON = clientIdentityJSON.nilIfBlank ?? ""
    }

    enum CodingKeys: String, CodingKey {
        case clusterID = "cluster_id"
        case connectionInput = "connection_input"
        case deviceID = "device_id"
        case deviceLabel = "device_label"
        case serverCAPem = "server_ca_pem"
        case clientIdentityJSON = "client_identity_json"
    }

    public func storedState(serverCAPemFallback: String? = nil) -> AppleStoredConnectionState {
        AppleStoredConnectionState(
            connectionInput: connectionInput,
            serverCAPem: serverCAPem ?? serverCAPemFallback,
            clientIdentityJSON: clientIdentityJSON,
            deviceID: deviceID,
            deviceLabel: deviceLabel,
            bootstrapInputDraft: nil
        )
    }
}

public protocol AppleBootstrapEnroller: Sendable {
    func enrollConnectionInput(
        _ connectionInput: String,
        deviceID: String?,
        label: String?
    ) throws -> AppleEnrolledConnection
}

public final class AppleConnectionSettingsStore: @unchecked Sendable {
    public static let defaultStateKey = "ironmesh.connection.state"
    public static let defaultLegacyDraftStateKey = "IronmeshIosApp.connectionDraft"

    private let defaults: UserDefaults
    private let stateKey: String
    let secretStore: any AppleSecretStore

    public init(
        defaults: UserDefaults = .standard,
        stateKey: String = defaultStateKey,
        secretStore: any AppleSecretStore = AppleKeychainSecretStore()
    ) {
        self.defaults = defaults
        self.stateKey = stateKey
        self.secretStore = secretStore
    }

    public convenience init(
        preferencesSuiteName: String?,
        keychainAccessGroup: String?,
        stateKey: String = defaultStateKey,
        secretStore: (any AppleSecretStore)? = nil
    ) {
        let normalizedSuiteName = preferencesSuiteName?.nilIfBlank
        let resolvedSecretStore = secretStore ?? AppleKeychainSecretStore(
            accessGroup: keychainAccessGroup
        )
        if let suiteName = normalizedSuiteName,
           let defaults = UserDefaults(suiteName: suiteName) {
            self.init(
                defaults: defaults,
                stateKey: stateKey,
                secretStore: resolvedSecretStore
            )
        } else {
            self.init(
                defaults: .standard,
                stateKey: stateKey,
                secretStore: resolvedSecretStore
            )
        }
    }

    public func load(
        legacyDraftDefaults: UserDefaults? = nil,
        legacyDraftStateKey: String = defaultLegacyDraftStateKey
    ) throws -> AppleStoredConnectionState? {
        let storedState = try loadPersistedState()
        let draftRecord = try legacyDraftDefaults.flatMap {
            try Self.legacyDraftRecord(defaults: $0, stateKey: legacyDraftStateKey)
        }
        let keychainIdentity = try secretStore.load()?.nilIfBlank
        let legacyIdentity = storedState?.clientIdentityJSON?.nilIfBlank
            ?? draftRecord?.identity
        let clientIdentity = keychainIdentity ?? legacyIdentity
        let hasLegacyPreferences =
            storedState?.clientIdentityJSON != nil || draftRecord != nil

        let sanitizedStateData: Data?
        if let storedState, storedState.clientIdentityJSON != nil {
            sanitizedStateData = try Self.encode(storedState.withoutClientIdentity)
        } else {
            sanitizedStateData = nil
        }

        if hasLegacyPreferences {
            if let clientIdentity {
                try secretStore.save(clientIdentity)
            } else {
                try secretStore.clear()
            }
        }

        // Remove legacy values only after the Keychain write above has succeeded.
        if let sanitizedStateData {
            defaults.set(sanitizedStateData, forKey: stateKey)
        }
        if let draftRecord, let legacyDraftDefaults {
            legacyDraftDefaults.set(
                draftRecord.sanitizedData,
                forKey: legacyDraftStateKey
            )
        }

        guard var state = storedState?.withoutClientIdentity else {
            return clientIdentity.map {
                AppleStoredConnectionState(clientIdentityJSON: $0)
            }
        }
        state.clientIdentityJSON = clientIdentity
        return state
    }

    public func save(_ state: AppleStoredConnectionState) throws {
        let sanitizedData = try Self.encode(state.withoutClientIdentity)
        if let clientIdentity = state.clientIdentityJSON?.nilIfBlank {
            try secretStore.save(clientIdentity)
        } else {
            try secretStore.clear()
        }
        defaults.set(sanitizedData, forKey: stateKey)
    }

    public func clear() throws {
        try secretStore.clear()
        defaults.removeObject(forKey: stateKey)
    }

    private func loadPersistedState() throws -> AppleStoredConnectionState? {
        guard let data = defaults.data(forKey: stateKey) else {
            return nil
        }
        return try JSONDecoder().decode(AppleStoredConnectionState.self, from: data)
    }

    private static func encode(_ state: AppleStoredConnectionState) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(state)
    }

    private static func legacyDraftRecord(
        defaults: UserDefaults,
        stateKey: String
    ) throws -> LegacyDraftRecord? {
        guard let data = defaults.data(forKey: stateKey),
              var object = try JSONSerialization.jsonObject(with: data)
                as? [String: Any],
              object.keys.contains("clientIdentityJSON")
        else {
            return nil
        }
        let identity = (object.removeValue(forKey: "clientIdentityJSON") as? String)?
            .nilIfBlank
        return LegacyDraftRecord(
            identity: identity,
            sanitizedData: try JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys]
            )
        )
    }
}

private struct LegacyDraftRecord {
    let identity: String?
    let sanitizedData: Data
}

extension AppleStoredConnectionState {
    fileprivate var withoutClientIdentity: AppleStoredConnectionState {
        AppleStoredConnectionState(
            connectionInput: connectionInput,
            serverCAPem: serverCAPem,
            clientIdentityJSON: nil,
            deviceID: deviceID,
            deviceLabel: deviceLabel,
            bootstrapInputDraft: bootstrapInputDraft
        )
    }
}
