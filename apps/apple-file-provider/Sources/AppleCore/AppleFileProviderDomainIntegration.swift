@preconcurrency import FileProvider
import Foundation

public struct AppleRegisteredFileProviderDomain: Equatable, Sendable {
    public let identifier: String
    public let displayName: String

    public init(identifier: String, displayName: String) {
        self.identifier = identifier
        self.displayName = displayName
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
    func domains() async throws -> [AppleRegisteredFileProviderDomain]
}

public struct AppleLiveFileProviderDomainManager: AppleFileProviderDomainManaging {
    public init() {}

    public func add(identifier: String, displayName: String) async throws {
        let domain = NSFileProviderDomain(
            identifier: NSFileProviderDomainIdentifier(rawValue: identifier),
            displayName: displayName
        )
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

    public func domains() async throws -> [AppleRegisteredFileProviderDomain] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[AppleRegisteredFileProviderDomain], any Error>) in
            NSFileProviderManager.getDomainsWithCompletionHandler { domains, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }

                let registeredDomains = domains.map {
                    AppleRegisteredFileProviderDomain(
                        identifier: $0.identifier.rawValue,
                        displayName: $0.displayName
                    )
                }
                continuation.resume(returning: registeredDomains)
            }
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
