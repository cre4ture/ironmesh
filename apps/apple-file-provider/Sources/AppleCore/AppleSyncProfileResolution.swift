import Foundation

public enum AppleSyncProfileResolutionError: LocalizedError, Equatable {
    case missingManagedProfile(String)

    public var errorDescription: String? {
        switch self {
        case .missingManagedProfile(let domainIdentifier):
            return "Sync profile configuration for Files domain '\(domainIdentifier)' is missing."
        }
    }
}

public enum AppleSyncProfileResolution {
    public static func resolve(
        domainIdentifier: String,
        storedProfile: AppleSyncProfile?,
        configuredProfile: AppleSyncProfile?,
        legacyDisplayName: String
    ) throws -> AppleSyncProfile {
        if let storedProfile {
            return storedProfile
        }
        if domainIdentifier.hasPrefix(AppleSyncProfile.managedDomainPrefix) {
            throw AppleSyncProfileResolutionError.missingManagedProfile(domainIdentifier)
        }
        if let configuredProfile {
            return configuredProfile
        }
        return AppleSyncProfile(
            id: "legacy-default",
            displayName: legacyDisplayName,
            networkPolicy: AppleSyncProfileNetworkPolicy(
                allowsExpensiveNetwork: true,
                allowsConstrainedNetwork: true
            ),
            powerPolicy: AppleSyncProfilePowerPolicy(defersInLowPowerMode: false)
        )
    }
}
