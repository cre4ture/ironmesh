import Foundation

public struct AppleSyncProfileDomainCoordinator: Sendable {
    private let manager: any AppleFileProviderDomainManaging

    public init(manager: any AppleFileProviderDomainManaging = AppleLiveFileProviderDomainManager()) {
        self.manager = manager
    }

    public func registeredProfiles(
        _ profiles: [AppleSyncProfile]
    ) async throws -> [String: AppleRegisteredFileProviderDomain] {
        let profileIdentifiers = Set(profiles.map(\.domainIdentifier))
        return try await manager.domains().reduce(
            into: [String: AppleRegisteredFileProviderDomain]()
        ) { result, domain in
            guard profileIdentifiers.contains(domain.identifier) else {
                return
            }
            guard let existing = result[domain.identifier] else {
                result[domain.identifier] = domain
                return
            }
            // Legacy registrations may contain duplicate identifiers. Prefer a connected domain,
            // then the lexicographically stable display name, rather than trapping the app.
            if (existing.isDisconnected && !domain.isDisconnected)
                || (existing.isDisconnected == domain.isDisconnected
                    && domain.displayName < existing.displayName)
            {
                result[domain.identifier] = domain
            }
        }
    }

    public func configure(_ profile: AppleSyncProfile) async throws {
        if let existing = try await manager.domains().first(where: {
            $0.identifier == profile.domainIdentifier
        }), existing.displayName == profile.displayName {
            if profile.lifecycle == .paused, !existing.isDisconnected {
                try await pause(profile)
            } else if profile.lifecycle == .active, existing.isDisconnected {
                try await resume(profile)
            }
            return
        }
        try await manager.add(
            identifier: profile.domainIdentifier,
            displayName: profile.displayName
        )
        if profile.lifecycle == .paused {
            try await pause(profile)
        }
    }

    /// Reconciles profiles independently so one damaged domain cannot prevent later profiles from
    /// being repaired after an app or extension restart.
    public func reconcile(_ profiles: [AppleSyncProfile]) async -> [String] {
        var errors: [String] = []
        for profile in profiles {
            do {
                try await configure(profile)
            } catch {
                errors.append("\(profile.displayName): \(error.localizedDescription)")
            }
        }
        return errors
    }

    public func pause(_ profile: AppleSyncProfile) async throws {
        guard try await contains(profile) else {
            return
        }
        try await manager.disconnect(
            identifier: profile.domainIdentifier,
            displayName: profile.displayName,
            reason: "Sync profile paused in BerryKeep."
        )
    }

    public func resume(_ profile: AppleSyncProfile) async throws {
        guard try await contains(profile) else {
            var activeProfile = profile
            activeProfile.lifecycle = .active
            try await configure(activeProfile)
            return
        }
        try await manager.reconnect(
            identifier: profile.domainIdentifier,
            displayName: profile.displayName
        )
        // Reconnect/persisted lifecycle is authoritative. A working-set signal only accelerates
        // discovery; Files will enumerate normally if that best-effort hint is unavailable.
        try? await signalChanges(profile)
    }

    public func remove(_ profile: AppleSyncProfile) async throws {
        guard try await contains(profile) else {
            return
        }
        try await manager.remove(
            identifier: profile.domainIdentifier,
            displayName: profile.displayName
        )
    }

    public func signalChanges(_ profile: AppleSyncProfile) async throws {
        guard try await contains(profile) else {
            return
        }
        try await manager.signalChanges(
            identifier: profile.domainIdentifier,
            displayName: profile.displayName
        )
    }

    private func contains(_ profile: AppleSyncProfile) async throws -> Bool {
        try await manager.domains().contains { $0.identifier == profile.domainIdentifier }
    }
}
