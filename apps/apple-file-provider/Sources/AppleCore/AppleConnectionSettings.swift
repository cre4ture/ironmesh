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

public struct AppleBootstrapEnrollmentResult: Sendable, Codable, Equatable {
    public var clusterID: String
    public var connectionBootstrapJSON: String?
    public var deviceID: String
    public var label: String?
    public var publicKeyPEM: String
    public var privateKeyPEM: String
    public var credentialPEM: String
    public var rendezvousClientIdentityPEM: String?
    public var serverBaseURL: String?
    public var serverCAPem: String?
    public var createdAtUnix: UInt64?
    public var expiresAtUnix: UInt64?
    public var clientIdentityJSON: String?

    public init(
        clusterID: String,
        connectionBootstrapJSON: String? = nil,
        deviceID: String,
        label: String? = nil,
        publicKeyPEM: String,
        privateKeyPEM: String,
        credentialPEM: String,
        rendezvousClientIdentityPEM: String? = nil,
        serverBaseURL: String? = nil,
        serverCAPem: String? = nil,
        createdAtUnix: UInt64? = nil,
        expiresAtUnix: UInt64? = nil,
        clientIdentityJSON: String? = nil
    ) {
        self.clusterID = clusterID
        self.connectionBootstrapJSON = connectionBootstrapJSON?.nilIfBlank
        self.deviceID = deviceID
        self.label = label?.nilIfBlank
        self.publicKeyPEM = publicKeyPEM
        self.privateKeyPEM = privateKeyPEM
        self.credentialPEM = credentialPEM
        self.rendezvousClientIdentityPEM = rendezvousClientIdentityPEM?.nilIfBlank
        self.serverBaseURL = serverBaseURL?.nilIfBlank
        self.serverCAPem = serverCAPem?.nilIfBlank
        self.createdAtUnix = createdAtUnix
        self.expiresAtUnix = expiresAtUnix
        self.clientIdentityJSON = clientIdentityJSON?.nilIfBlank
    }

    enum CodingKeys: String, CodingKey {
        case clusterID = "cluster_id"
        case connectionBootstrapJSON = "connection_bootstrap_json"
        case deviceID = "device_id"
        case label
        case deviceLabel = "device_label"
        case publicKeyPEM = "public_key_pem"
        case privateKeyPEM = "private_key_pem"
        case credentialPEM = "credential_pem"
        case rendezvousClientIdentityPEM = "rendezvous_client_identity_pem"
        case serverBaseURL = "server_base_url"
        case serverCAPem = "server_ca_pem"
        case createdAtUnix = "created_at_unix"
        case expiresAtUnix = "expires_at_unix"
        case clientIdentityJSON = "client_identity_json"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let label = try container.decodeIfPresent(String.self, forKey: .label)
        let deviceLabel = try container.decodeIfPresent(String.self, forKey: .deviceLabel)

        self.init(
            clusterID: try container.decode(String.self, forKey: .clusterID),
            connectionBootstrapJSON: try container.decodeIfPresent(
                String.self,
                forKey: .connectionBootstrapJSON
            ),
            deviceID: try container.decode(String.self, forKey: .deviceID),
            label: label ?? deviceLabel,
            publicKeyPEM: try container.decode(String.self, forKey: .publicKeyPEM),
            privateKeyPEM: try container.decode(String.self, forKey: .privateKeyPEM),
            credentialPEM: try container.decode(String.self, forKey: .credentialPEM),
            rendezvousClientIdentityPEM: try container.decodeIfPresent(
                String.self,
                forKey: .rendezvousClientIdentityPEM
            ),
            serverBaseURL: try container.decodeIfPresent(String.self, forKey: .serverBaseURL),
            serverCAPem: try container.decodeIfPresent(String.self, forKey: .serverCAPem),
            createdAtUnix: try container.decodeIfPresent(UInt64.self, forKey: .createdAtUnix),
            expiresAtUnix: try container.decodeIfPresent(UInt64.self, forKey: .expiresAtUnix),
            clientIdentityJSON: try container.decodeIfPresent(
                String.self,
                forKey: .clientIdentityJSON
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(clusterID, forKey: .clusterID)
        try container.encodeIfPresent(connectionBootstrapJSON, forKey: .connectionBootstrapJSON)
        try container.encode(deviceID, forKey: .deviceID)
        try container.encodeIfPresent(label, forKey: .label)
        try container.encode(publicKeyPEM, forKey: .publicKeyPEM)
        try container.encode(privateKeyPEM, forKey: .privateKeyPEM)
        try container.encode(credentialPEM, forKey: .credentialPEM)
        try container.encodeIfPresent(
            rendezvousClientIdentityPEM,
            forKey: .rendezvousClientIdentityPEM
        )
        try container.encodeIfPresent(serverBaseURL, forKey: .serverBaseURL)
        try container.encodeIfPresent(serverCAPem, forKey: .serverCAPem)
        try container.encodeIfPresent(createdAtUnix, forKey: .createdAtUnix)
        try container.encodeIfPresent(expiresAtUnix, forKey: .expiresAtUnix)
        try container.encodeIfPresent(clientIdentityJSON, forKey: .clientIdentityJSON)
    }

    public var resolvedConnectionInput: String? {
        connectionBootstrapJSON?.nilIfBlank ?? serverBaseURL?.nilIfBlank
    }

    public func resolvedClientIdentityJSON() throws -> String {
        if let clientIdentityJSON = clientIdentityJSON?.nilIfBlank {
            return clientIdentityJSON
        }

        let payload = AppleClientIdentityMaterialPayload(
            clusterID: clusterID,
            deviceID: deviceID,
            label: label,
            privateKeyPEM: privateKeyPEM,
            publicKeyPEM: publicKeyPEM,
            credentialPEM: credentialPEM,
            rendezvousClientIdentityPEM: rendezvousClientIdentityPEM,
            issuedAtUnix: createdAtUnix,
            expiresAtUnix: expiresAtUnix
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(
            data: try encoder.encode(payload),
            encoding: .utf8
        ) ?? ""
    }

    public func applying(
        to state: AppleStoredConnectionState,
        fallbackConnectionInput: String
    ) throws -> AppleStoredConnectionState {
        AppleStoredConnectionState(
            connectionInput: resolvedConnectionInput ?? state.connectionInput ?? fallbackConnectionInput,
            serverCAPem: serverCAPem ?? state.serverCAPem,
            clientIdentityJSON: try resolvedClientIdentityJSON(),
            deviceID: deviceID,
            deviceLabel: label ?? state.deviceLabel,
            bootstrapInputDraft: nil
        )
    }
}

public protocol AppleBootstrapEnroller: Sendable {
    func enrollConnectionInput(
        _ connectionInput: String,
        deviceID: String?,
        label: String?
    ) throws -> AppleBootstrapEnrollmentResult
}

public final class AppleConnectionSettingsStore: @unchecked Sendable {
    public static let defaultStateKey = "ironmesh.connection.state"

    private let defaults: UserDefaults
    private let stateKey: String

    public init(defaults: UserDefaults = .standard, stateKey: String = defaultStateKey) {
        self.defaults = defaults
        self.stateKey = stateKey
    }

    public convenience init(suiteName: String?, stateKey: String = defaultStateKey) {
        if let suiteName = suiteName?.nilIfBlank,
           let defaults = UserDefaults(suiteName: suiteName) {
            self.init(defaults: defaults, stateKey: stateKey)
        } else {
            self.init(defaults: .standard, stateKey: stateKey)
        }
    }

    public func load() -> AppleStoredConnectionState? {
        guard let data = defaults.data(forKey: stateKey) else {
            return nil
        }
        return try? JSONDecoder().decode(AppleStoredConnectionState.self, from: data)
    }

    public func save(_ state: AppleStoredConnectionState) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        defaults.set(try encoder.encode(state), forKey: stateKey)
    }

    public func clear() {
        defaults.removeObject(forKey: stateKey)
    }
}

private struct AppleClientIdentityMaterialPayload: Codable, Equatable {
    let clusterID: String
    let deviceID: String
    let label: String?
    let privateKeyPEM: String
    let publicKeyPEM: String
    let credentialPEM: String
    let rendezvousClientIdentityPEM: String?
    let issuedAtUnix: UInt64?
    let expiresAtUnix: UInt64?

    enum CodingKeys: String, CodingKey {
        case clusterID = "cluster_id"
        case deviceID = "device_id"
        case label
        case privateKeyPEM = "private_key_pem"
        case publicKeyPEM = "public_key_pem"
        case credentialPEM = "credential_pem"
        case rendezvousClientIdentityPEM = "rendezvous_client_identity_pem"
        case issuedAtUnix = "issued_at_unix"
        case expiresAtUnix = "expires_at_unix"
    }
}
