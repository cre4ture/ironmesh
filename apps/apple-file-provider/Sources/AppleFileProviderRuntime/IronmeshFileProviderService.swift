import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

final class IronmeshFileProviderService: @unchecked Sendable {
    let configuration: IronmeshBundleConfiguration

    let bridge: AppleCFacadeBridge
    let ffi: AppleManualCBridgeFFI
    let cache: IronmeshIdentifierPathCache
    let settingsStore: AppleConnectionSettingsStore
    let profileStore: AppleSyncProfileStore
    let pathMapper: AppleProfilePathMapper
    let environment: any IronmeshSyncEnvironmentProviding
    let changeJournal: AppleRemoteChangeJournalStore
    let lock = NSLock()
    var connected = false
    var connectedConfiguration: AppleConnectionConfiguration?

    init(
        configuration: IronmeshBundleConfiguration = IronmeshBundleConfiguration(),
        ffi: AppleManualCBridgeFFI = IronmeshRustFFIAdapter(),
        settingsStore: AppleConnectionSettingsStore? = nil,
        profileStore: AppleSyncProfileStore? = nil,
        environment: any IronmeshSyncEnvironmentProviding = IronmeshLiveSyncEnvironment.shared,
        changeJournal: AppleRemoteChangeJournalStore? = nil
    ) {
        self.configuration = configuration
        self.ffi = ffi
        bridge = AppleCFacadeBridge(ffi: ffi)
        cache = IronmeshIdentifierPathCache(domainIdentifier: configuration.domainIdentifier)
        self.settingsStore = settingsStore ?? configuration.makeSettingsStore()
        self.profileStore = profileStore ?? configuration.makeProfileStore()
        pathMapper = AppleProfilePathMapper(
            remotePrefix: configuration.syncProfile?.remotePrefix ?? ""
        )
        self.environment = environment
        self.changeJournal = changeJournal ?? AppleRemoteChangeJournalStore(
            fileURL: ironmeshChangeJournalURL(domainIdentifier: configuration.domainIdentifier)
        )
    }
}
