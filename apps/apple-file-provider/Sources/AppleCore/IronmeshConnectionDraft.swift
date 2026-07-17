import Foundation

public struct IronmeshConnectionDraft: Codable, Equatable, Sendable {
    public var deviceLabel: String
    public var directConnectionInput: String
    public var bootstrapInput: String
    public var serverCAPem: String
    public var clientIdentityJSON: String
    public var enrolledDeviceID: String
    public var domainIdentifier: String
    public var domainDisplayName: String

    public init(
        deviceLabel: String = "",
        directConnectionInput: String = "",
        bootstrapInput: String = "",
        serverCAPem: String = "",
        clientIdentityJSON: String = "",
        enrolledDeviceID: String = "",
        domainIdentifier: String = "dev.ironmesh.default",
        domainDisplayName: String = "IronMesh"
    ) {
        self.deviceLabel = deviceLabel
        self.directConnectionInput = directConnectionInput
        self.bootstrapInput = bootstrapInput
        self.serverCAPem = serverCAPem
        self.clientIdentityJSON = clientIdentityJSON
        self.enrolledDeviceID = enrolledDeviceID
        self.domainIdentifier = domainIdentifier
        self.domainDisplayName = domainDisplayName
    }

    public var effectiveConnectionInput: String {
        bootstrapInput.nilIfBlank ?? directConnectionInput.nilIfBlank ?? ""
    }

    public var isConfigured: Bool {
        effectiveConnectionInput.nilIfBlank != nil
    }

    public var hasBootstrapPayload: Bool {
        bootstrapInput.nilIfBlank != nil
    }

    public var hasClientIdentity: Bool {
        clientIdentityJSON.nilIfBlank != nil
    }

    public var hasEnrolledDevice: Bool {
        enrolledDeviceID.nilIfBlank != nil
    }

    public var requiresEnrollment: Bool {
        hasBootstrapPayload && !hasClientIdentity
    }

    public var connectionConfiguration: AppleConnectionConfiguration? {
        guard let connectionInput = effectiveConnectionInput.nilIfBlank else {
            return nil
        }

        return AppleConnectionConfiguration(
            connectionInput: connectionInput,
            serverCAPem: serverCAPem.nilIfBlank,
            clientIdentityJSON: clientIdentityJSON.nilIfBlank
        )
    }

    public var normalizedConnectionInput: String? {
        connectionConfiguration?.normalizedConnectionInput
    }

    public var directConnectionURL: URL? {
        guard let directConnectionInput = directConnectionInput.nilIfBlank else {
            return nil
        }

        let normalized = AppleConnectionConfiguration(connectionInput: directConnectionInput)
            .normalizedConnectionInput
        return URL(string: normalized)
    }

    public var setupSummary: String {
        if let normalizedConnectionInput {
            if hasBootstrapPayload {
                return "Bootstrap bundle ready for \(domainDisplayName.nilIfBlank ?? "IronMesh")."
            }
            return "Direct route \(normalizedConnectionInput)"
        }

        return "Add a bootstrap bundle or direct route to continue."
    }

    public var enrollmentSummary: String {
        if let enrolledDeviceID = enrolledDeviceID.nilIfBlank {
            if let label = deviceLabel.nilIfBlank {
                return "Enrolled as \(label) (\(enrolledDeviceID))."
            }
            return "Enrolled device \(enrolledDeviceID)."
        }

        switch (hasBootstrapPayload, hasClientIdentity) {
        case (true, true):
            return "Bootstrap bundle imported and client identity attached."
        case (true, false):
            return "Bootstrap bundle imported. Enroll this device to mint client identity material."
        case (false, true):
            return "Direct route configured with client identity."
        case (false, false):
            return isConfigured ? "Direct route configured." : "No connection target configured yet."
        }
    }

    public var identitySummary: String {
        if let enrolledDeviceID = enrolledDeviceID.nilIfBlank {
            return "Client identity attached for \(enrolledDeviceID)."
        }
        return hasClientIdentity ? "Client identity attached." : "No client identity attached."
    }

    public func appliedConnectionState(defaultConnectionInput: String) -> AppleStoredConnectionState {
        AppleStoredConnectionState(
            connectionInput: effectiveConnectionInput.nilIfBlank ?? defaultConnectionInput,
            serverCAPem: serverCAPem.nilIfBlank,
            clientIdentityJSON: clientIdentityJSON.nilIfBlank,
            deviceID: enrolledDeviceID.nilIfBlank,
            deviceLabel: deviceLabel.nilIfBlank,
            bootstrapInputDraft: bootstrapInput.nilIfBlank
        )
    }

    @discardableResult
    public mutating func applyScannedCode(_ scannedValue: String) -> Bool {
        guard let payload = Self.scannedConnectionPayload(from: scannedValue) else {
            return false
        }

        if Self.looksLikeBootstrap(payload) {
            bootstrapInput = payload
        } else {
            directConnectionInput = payload
        }

        return true
    }

    public static func scannedConnectionPayload(from scannedValue: String) -> String? {
        let trimmed = scannedValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }

        if let url = URL(string: trimmed),
           let scheme = url.scheme?.lowercased(),
           scheme == "ironmesh",
           let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        {
            let preferredQueryNames = ["bootstrap", "payload", "connection", "url"]
            for name in preferredQueryNames {
                if let value = components.queryItems?
                    .first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame })?.value,
                   let decoded = normalizedScannedPayload(value)
                {
                    return decoded
                }
            }
        }

        return normalizedScannedPayload(trimmed)
    }

    public static func looksLikeBootstrap(_ value: String) -> Bool {
        value.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{")
    }

    private static func normalizedScannedPayload(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }

        if trimmed.hasPrefix("{") || trimmed.contains("://") {
            return trimmed
        }

        if let decoded = trimmed.removingPercentEncoding,
           decoded != trimmed,
           (decoded.hasPrefix("{") || decoded.contains("://"))
        {
            return decoded
        }

        return trimmed
    }
}
