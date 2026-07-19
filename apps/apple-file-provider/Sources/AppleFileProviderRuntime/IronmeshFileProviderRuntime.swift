import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

struct IronmeshBundleConfiguration {
    let domainIdentifier: String
    let domainDisplayName: String
    let connectionInput: String
    let appGroupIdentifier: String?
    let keychainAccessGroup: String?
    let syncProfile: AppleSyncProfile?

    init(
        domainIdentifier: String,
        domainDisplayName: String = "IronMesh",
        connectionInput: String = "127.0.0.1:18080",
        appGroupIdentifier: String? = nil,
        keychainAccessGroup: String? = nil,
        syncProfile: AppleSyncProfile? = nil
    ) {
        self.domainIdentifier = domainIdentifier.nilIfBlank ?? "dev.ironmesh.default"
        self.domainDisplayName = domainDisplayName.nilIfBlank ?? "IronMesh"
        self.connectionInput = connectionInput.nilIfBlank ?? "127.0.0.1:18080"
        self.appGroupIdentifier = appGroupIdentifier.nilIfBlank
        self.keychainAccessGroup = keychainAccessGroup.nilIfBlank
        self.syncProfile = syncProfile
    }

    init(bundle: Bundle = .main) {
        let info = bundle.infoDictionary ?? [:]
        domainIdentifier = (info["IronmeshDomainIdentifier"] as? String)?.nilIfBlank ?? "dev.ironmesh.default"
        domainDisplayName = (info["IronmeshDomainDisplayName"] as? String)?.nilIfBlank ?? "IronMesh"
        connectionInput = (info["IronmeshConnectionInput"] as? String)?.nilIfBlank ?? "127.0.0.1:18080"
        appGroupIdentifier = (info["IronmeshAppGroupIdentifier"] as? String)?.nilIfBlank
        keychainAccessGroup = (info["IronmeshKeychainAccessGroup"] as? String)?.nilIfBlank
        syncProfile = nil
    }

    init(bundle: Bundle, domain: NSFileProviderDomain, syncProfile: AppleSyncProfile?) {
        let bundled = Self(bundle: bundle)
        domainIdentifier = domain.identifier.rawValue
        domainDisplayName = syncProfile?.displayName ?? domain.displayName
        connectionInput = bundled.connectionInput
        appGroupIdentifier = bundled.appGroupIdentifier
        keychainAccessGroup = bundled.keychainAccessGroup
        self.syncProfile = syncProfile
    }

    var defaultConnectionConfiguration: AppleConnectionConfiguration {
        AppleConnectionConfiguration(connectionInput: connectionInput)
    }

    var domain: NSFileProviderDomain {
        NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: domainIdentifier), displayName: domainDisplayName)
    }

    func makeSettingsStore() -> AppleConnectionSettingsStore {
        AppleConnectionSettingsStore(
            preferencesSuiteName: appGroupIdentifier,
            keychainAccessGroup: keychainAccessGroup
        )
    }

    func makeProfileStore() -> AppleSyncProfileStore {
        AppleSyncProfileStore(preferencesSuiteName: appGroupIdentifier)
    }
}
