import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

open class IronmeshFileProviderExtensionHost: NSObject, NSFileProviderReplicatedExtension, @unchecked Sendable {
    public let domain: NSFileProviderDomain
    let service: IronmeshFileProviderService
    let workingSetSignals: IronmeshWorkingSetSignalCoordinator

    public required init(domain: NSFileProviderDomain) {
        self.domain = domain
        let bundle = Bundle(for: Self.self)
        let bundledConfiguration = IronmeshBundleConfiguration(bundle: bundle)
        let profile = try? bundledConfiguration.makeProfileStore().profile(
            domainIdentifier: domain.identifier.rawValue
        )
        let configuration = IronmeshBundleConfiguration(
            bundle: bundle,
            domain: domain,
            syncProfile: profile
        )
        service = IronmeshFileProviderService(configuration: configuration)
        workingSetSignals = IronmeshWorkingSetSignalCoordinator(configuration: configuration)
        super.init()
        workingSetSignals.start()
    }

    deinit {
        workingSetSignals.invalidate()
    }

    public func invalidate() {
        workingSetSignals.invalidate()
    }
}
