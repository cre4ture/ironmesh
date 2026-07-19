import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

extension IronmeshFileProviderService {
    func registerDomain(completionHandler: @escaping (Error?) -> Void) {
        let completion = UncheckedBox(completionHandler)
        NSFileProviderManager.add(configuration.domain) { error in
            completion.value(error)
        }
    }

    func currentConnectionConfiguration() throws -> AppleConnectionConfiguration {
        let stored = try settingsStore.load()
        return stored?.effectiveConfiguration(fallback: configuration.defaultConnectionConfiguration)
            ?? configuration.defaultConnectionConfiguration
    }

    func storedConnectionState() throws -> AppleStoredConnectionState {
        try settingsStore.load() ?? AppleStoredConnectionState(
            connectionInput: configuration.defaultConnectionConfiguration.connectionInput
        )
    }

    func saveConnectionState(_ state: AppleStoredConnectionState, reconnect: Bool = true) throws {
        try ffi.stopWebUi()
        try settingsStore.save(state)
        if reconnect {
            resetConnection()
        }
    }

    func clearStoredConnectionState() throws {
        try ffi.stopWebUi()
        try settingsStore.clear()
        resetConnection()
    }

    func startWebUi() throws -> AppleWebUiSession {
        try enforceProfileConstraints()
        let connectionConfiguration = try currentConnectionConfiguration()
        let responseJSON = try ffi.startWebUi(
            connectionInput: connectionConfiguration.normalizedConnectionInput,
            serverCAPem: connectionConfiguration.serverCAPem,
            clientIdentityJSON: connectionConfiguration.clientIdentityJSON
        )
        return try AppleWebUiSession(responseJSON: responseJSON)
    }

    func connectIfNeeded() throws {
        try enforceProfileConstraints()
        let configuration = try currentConnectionConfiguration()
        lock.lock()
        let alreadyConnected = connected
        let currentConfiguration = connectedConfiguration
        lock.unlock()

        if alreadyConnected, currentConfiguration == configuration {
            return
        }

        _ = try bridge.connect(configuration)

        lock.lock()
        connected = true
        connectedConfiguration = configuration
        lock.unlock()
    }

    func enforceProfileConstraints() throws {
        let profile = try currentProfile()
        let decision = AppleSyncConstraintEvaluator.evaluate(
            profile: profile,
            environment: environment.snapshot()
        )
        if case .blocked(let reason) = decision {
            throw ironmeshConstraintError(reason)
        }
    }

    func currentProfile() throws -> AppleSyncProfile {
        do {
            return try AppleSyncProfileResolution.resolve(
                domainIdentifier: configuration.domainIdentifier,
                storedProfile: try profileStore.profile(
                    domainIdentifier: configuration.domainIdentifier
                ),
                configuredProfile: configuration.syncProfile,
                legacyDisplayName: configuration.domainDisplayName
            )
        } catch let error as AppleSyncProfileResolutionError {
            throw ironmeshConstraintError(error.localizedDescription)
        }
    }

    func resetConnection() {
        try? ffi.stopWebUi()
        lock.lock()
        connected = false
        connectedConfiguration = nil
        lock.unlock()
    }
}
