@preconcurrency import FileProvider
import Foundation

public struct AppleRegisteredFileProviderDomain: Equatable, Sendable {
    public let identifier: String
    public let displayName: String
    public let isDisconnected: Bool

    public init(
        identifier: String,
        displayName: String,
        isDisconnected: Bool = false
    ) {
        self.identifier = identifier
        self.displayName = displayName
        self.isDisconnected = isDisconnected
    }
}

public enum AppleFileProviderDomainRegistrationState: Equatable, Sendable {
    case unchecked
    case checking
    case registered(displayName: String)
    case missing
    case failed(String)

    public var title: String {
        switch self {
        case .unchecked:
            return "Domain not checked yet"
        case .checking:
            return "Checking File Provider domain"
        case .registered:
            return "Domain registered"
        case .missing:
            return "Domain not registered"
        case .failed:
            return "Domain check failed"
        }
    }

    public var detail: String {
        switch self {
        case .unchecked:
            return "Use Files integration to register the File Provider domain."
        case .checking:
            return "Inspecting currently registered provider domains."
        case .registered(let displayName):
            return "Files can expose the provider as \(displayName)."
        case .missing:
            return "Register the domain to hand off browsing into Files."
        case .failed(let message):
            return message
        }
    }

    public var isRegistered: Bool {
        if case .registered = self {
            return true
        }
        return false
    }
}

public struct AppleFileProviderDomainRegistrationResult: Equatable, Sendable {
    public let state: AppleFileProviderDomainRegistrationState
    public let identifier: String
    public let wasCreated: Bool

    public init(
        state: AppleFileProviderDomainRegistrationState,
        identifier: String,
        wasCreated: Bool
    ) {
        self.state = state
        self.identifier = identifier
        self.wasCreated = wasCreated
    }
}

public protocol AppleFileProviderDomainManaging: Sendable {
    func add(identifier: String, displayName: String) async throws
    func remove(identifier: String, displayName: String) async throws
    func disconnect(identifier: String, displayName: String, reason: String) async throws
    func reconnect(identifier: String, displayName: String) async throws
    func signalChanges(identifier: String, displayName: String) async throws
    func domains() async throws -> [AppleRegisteredFileProviderDomain]
}

public struct AppleLiveFileProviderDomainManager: AppleFileProviderDomainManaging {
    public init() {}

    public func add(identifier: String, displayName: String) async throws {
        let domain = domain(identifier: identifier, displayName: displayName)
        let _: Void = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            NSFileProviderManager.add(domain) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    public func remove(identifier: String, displayName: String) async throws {
        let domain = domain(identifier: identifier, displayName: displayName)
        let _: Void = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            NSFileProviderManager.remove(domain) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    public func disconnect(
        identifier: String,
        displayName: String,
        reason: String
    ) async throws {
        #if os(macOS)
        let manager = try manager(identifier: identifier, displayName: displayName)
        let _: Void = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            manager.disconnect(reason: reason, options: []) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
        #else
        // iOS does not expose NSFileProviderManager.disconnect. The shared profile lifecycle is
        // read before every extension operation, so persisting `.paused` is the authoritative
        // iOS gate. Keep the domain registered to preserve materialized and queued user data.
        _ = identifier
        _ = displayName
        _ = reason
        #endif
    }

    public func reconnect(identifier: String, displayName: String) async throws {
        #if os(macOS)
        let manager = try manager(identifier: identifier, displayName: displayName)
        let _: Void = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            manager.reconnect { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
        #else
        _ = identifier
        _ = displayName
        #endif
    }

    public func signalChanges(identifier: String, displayName: String) async throws {
        let manager = try manager(identifier: identifier, displayName: displayName)
        let _: Void = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            manager.signalEnumerator(for: .workingSet) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    public func domains() async throws -> [AppleRegisteredFileProviderDomain] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[AppleRegisteredFileProviderDomain], any Error>) in
            NSFileProviderManager.getDomainsWithCompletionHandler { domains, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }

                let registeredDomains = domains.map {
                    #if os(macOS)
                    let isDisconnected = $0.isDisconnected
                    #else
                    let isDisconnected = false
                    #endif
                    return AppleRegisteredFileProviderDomain(
                        identifier: $0.identifier.rawValue,
                        displayName: $0.displayName,
                        isDisconnected: isDisconnected
                    )
                }
                continuation.resume(returning: registeredDomains)
            }
        }
    }

    private func domain(identifier: String, displayName: String) -> NSFileProviderDomain {
        NSFileProviderDomain(
            identifier: NSFileProviderDomainIdentifier(rawValue: identifier),
            displayName: displayName
        )
    }

    private func manager(identifier: String, displayName: String) throws -> NSFileProviderManager {
        let domain = domain(identifier: identifier, displayName: displayName)
        guard let manager = NSFileProviderManager(for: domain) else {
            throw AppleFileProviderDomainManagementError.managerUnavailable(identifier)
        }
        return manager
    }
}

public enum AppleFileProviderDomainManagementError: LocalizedError, Equatable {
    case managerUnavailable(String)

    public var errorDescription: String? {
        switch self {
        case .managerUnavailable(let identifier):
            return "File Provider manager for domain '\(identifier)' is unavailable."
        }
    }
}

public struct AppleFileProviderDomainCoordinator: Sendable {
    private let manager: any AppleFileProviderDomainManaging

    public init(manager: any AppleFileProviderDomainManaging = AppleLiveFileProviderDomainManager()) {
        self.manager = manager
    }

    public func refresh(
        expectedIdentifier: String
    ) async -> AppleFileProviderDomainRegistrationState {
        do {
            return domainState(
                from: try await manager.domains(),
                expectedIdentifier: expectedIdentifier
            )
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    public func register(
        identifier: String,
        displayName: String
    ) async -> AppleFileProviderDomainRegistrationResult {
        do {
            let domains = try await manager.domains()
            if let existing = matchingDomain(in: domains, expectedIdentifier: identifier) {
                return AppleFileProviderDomainRegistrationResult(
                    state: .registered(displayName: existing.displayName),
                    identifier: identifier,
                    wasCreated: false
                )
            }

            try await manager.add(identifier: identifier, displayName: displayName)
            return AppleFileProviderDomainRegistrationResult(
                state: .registered(displayName: displayName),
                identifier: identifier,
                wasCreated: true
            )
        } catch {
            if let registeredState = await registeredStateAfterFailedAdd(expectedIdentifier: identifier) {
                return AppleFileProviderDomainRegistrationResult(
                    state: registeredState,
                    identifier: identifier,
                    wasCreated: false
                )
            }

            return AppleFileProviderDomainRegistrationResult(
                state: .failed(error.localizedDescription),
                identifier: identifier,
                wasCreated: false
            )
        }
    }

    private func registeredStateAfterFailedAdd(
        expectedIdentifier: String
    ) async -> AppleFileProviderDomainRegistrationState? {
        do {
            let domains = try await manager.domains()
            guard let existing = matchingDomain(in: domains, expectedIdentifier: expectedIdentifier) else {
                return nil
            }
            return .registered(displayName: existing.displayName)
        } catch {
            return nil
        }
    }

    private func domainState(
        from domains: [AppleRegisteredFileProviderDomain],
        expectedIdentifier: String
    ) -> AppleFileProviderDomainRegistrationState {
        guard let existing = matchingDomain(in: domains, expectedIdentifier: expectedIdentifier) else {
            return .missing
        }
        return .registered(displayName: existing.displayName)
    }

    private func matchingDomain(
        in domains: [AppleRegisteredFileProviderDomain],
        expectedIdentifier: String
    ) -> AppleRegisteredFileProviderDomain? {
        domains.first { $0.identifier == expectedIdentifier }
    }
}
