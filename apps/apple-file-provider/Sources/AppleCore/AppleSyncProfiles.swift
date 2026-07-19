import Foundation

public enum AppleSyncProfileLifecycle: String, Codable, CaseIterable, Sendable {
    case active
    case paused
}

/// The Android client also owns one enrolled device connection and lets profiles select a scope
/// below it. Keeping the reference explicit prevents a profile from silently becoming a second
/// credential store while still leaving room for another connection source in the future.
public enum AppleSyncProfileConnectionReference: String, Codable, CaseIterable, Sendable {
    case sharedDevice = "shared_device"
}

public struct AppleSyncProfileNetworkPolicy: Codable, Equatable, Sendable {
    public var allowsExpensiveNetwork: Bool
    public var allowsConstrainedNetwork: Bool

    public init(
        allowsExpensiveNetwork: Bool = false,
        allowsConstrainedNetwork: Bool = false
    ) {
        self.allowsExpensiveNetwork = allowsExpensiveNetwork
        self.allowsConstrainedNetwork = allowsConstrainedNetwork
    }
}

public struct AppleSyncProfilePowerPolicy: Codable, Equatable, Sendable {
    public var defersInLowPowerMode: Bool

    public init(defersInLowPowerMode: Bool = true) {
        self.defersInLowPowerMode = defersInLowPowerMode
    }
}

public enum AppleSyncProfileContentPolicy: String, Codable, CaseIterable, Sendable {
    /// iOS materializes files on demand and owns offline pinning through Files' “Keep Downloaded”
    /// action. File Provider does not expose a profile-level eager-retention policy on iOS.
    case systemManaged = "system_managed"
}

public struct AppleSyncProfile: Codable, Equatable, Identifiable, Sendable {
    public static let managedDomainPrefix = "dev.ironmesh.profile."

    public var id: String
    public var displayName: String
    public var remotePrefix: String
    public var depth: Int
    public var lifecycle: AppleSyncProfileLifecycle
    public var connectionReference: AppleSyncProfileConnectionReference
    public var networkPolicy: AppleSyncProfileNetworkPolicy
    public var powerPolicy: AppleSyncProfilePowerPolicy
    public var contentPolicy: AppleSyncProfileContentPolicy

    public init(
        id: String = UUID().uuidString.lowercased(),
        displayName: String,
        remotePrefix: String = "",
        depth: Int = 64,
        lifecycle: AppleSyncProfileLifecycle = .active,
        connectionReference: AppleSyncProfileConnectionReference = .sharedDevice,
        networkPolicy: AppleSyncProfileNetworkPolicy = AppleSyncProfileNetworkPolicy(),
        powerPolicy: AppleSyncProfilePowerPolicy = AppleSyncProfilePowerPolicy(),
        contentPolicy: AppleSyncProfileContentPolicy = .systemManaged
    ) {
        self.id = Self.normalizedIdentifier(id)
        self.displayName = displayName.nilIfBlank ?? "BerryKeep"
        self.remotePrefix = normalizedPath(remotePrefix)
        self.depth = max(depth, 1)
        self.lifecycle = lifecycle
        self.connectionReference = connectionReference
        self.networkPolicy = networkPolicy
        self.powerPolicy = powerPolicy
        self.contentPolicy = contentPolicy
    }

    public var domainIdentifier: String {
        "\(Self.managedDomainPrefix)\(id)"
    }

    public var scopeSummary: String {
        remotePrefix.isEmpty ? "/" : "/\(remotePrefix)"
    }

    private static func normalizedIdentifier(_ value: String) -> String {
        let normalized = value
            .lowercased()
            .map { character in
                character.isLetter || character.isNumber || character == "-" ? character : "-"
            }
        let result = String(normalized).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return result.nilIfBlank ?? UUID().uuidString.lowercased()
    }
}

public final class AppleSyncProfileStore: @unchecked Sendable {
    public static let defaultProfilesKey = "ironmesh.sync.profiles.v1"

    private let defaults: UserDefaults
    private let profilesKey: String
    private let lock = NSLock()

    public init(
        defaults: UserDefaults = .standard,
        profilesKey: String = defaultProfilesKey
    ) {
        self.defaults = defaults
        self.profilesKey = profilesKey
    }

    public convenience init(preferencesSuiteName: String?, profilesKey: String = defaultProfilesKey) {
        if let suiteName = preferencesSuiteName?.nilIfBlank,
           let defaults = UserDefaults(suiteName: suiteName) {
            self.init(defaults: defaults, profilesKey: profilesKey)
        } else {
            self.init(defaults: .standard, profilesKey: profilesKey)
        }
    }

    public func load() throws -> [AppleSyncProfile] {
        lock.lock()
        defer { lock.unlock() }
        return try loadLocked()
    }

    @discardableResult
    public func upsert(_ profile: AppleSyncProfile) throws -> [AppleSyncProfile] {
        lock.lock()
        defer { lock.unlock() }

        var profiles = try loadLocked()
        profiles.removeAll { $0.id == profile.id || $0.domainIdentifier == profile.domainIdentifier }
        profiles.append(profile)
        try persistLocked(profiles)
        return Self.sorted(profiles)
    }

    @discardableResult
    public func setLifecycle(
        _ lifecycle: AppleSyncProfileLifecycle,
        profileID: String
    ) throws -> [AppleSyncProfile] {
        lock.lock()
        defer { lock.unlock() }

        var profiles = try loadLocked()
        guard let index = profiles.firstIndex(where: { $0.id == profileID }) else {
            throw AppleSyncProfileStoreError.profileNotFound(profileID)
        }
        profiles[index].lifecycle = lifecycle
        try persistLocked(profiles)
        return Self.sorted(profiles)
    }

    @discardableResult
    public func remove(profileID: String) throws -> [AppleSyncProfile] {
        lock.lock()
        defer { lock.unlock() }

        var profiles = try loadLocked()
        guard profiles.contains(where: { $0.id == profileID }) else {
            throw AppleSyncProfileStoreError.profileNotFound(profileID)
        }
        profiles.removeAll { $0.id == profileID }
        try persistLocked(profiles)
        return Self.sorted(profiles)
    }

    public func profile(domainIdentifier: String) throws -> AppleSyncProfile? {
        try load().first { $0.domainIdentifier == domainIdentifier }
    }

    private func loadLocked() throws -> [AppleSyncProfile] {
        guard let data = defaults.data(forKey: profilesKey) else {
            return []
        }
        return Self.sorted(try JSONDecoder().decode([AppleSyncProfile].self, from: data))
    }

    private func persistLocked(_ profiles: [AppleSyncProfile]) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        defaults.set(try encoder.encode(Self.sorted(profiles)), forKey: profilesKey)
    }

    private static func sorted(_ profiles: [AppleSyncProfile]) -> [AppleSyncProfile] {
        profiles.sorted {
            let displayOrder = $0.displayName.localizedCaseInsensitiveCompare($1.displayName)
            if displayOrder != .orderedSame {
                return displayOrder == .orderedAscending
            }
            return $0.id < $1.id
        }
    }
}

public enum AppleSyncProfileStoreError: LocalizedError, Equatable {
    case profileNotFound(String)

    public var errorDescription: String? {
        switch self {
        case .profileNotFound(let profileID):
            return "Sync profile '\(profileID)' was not found."
        }
    }
}
