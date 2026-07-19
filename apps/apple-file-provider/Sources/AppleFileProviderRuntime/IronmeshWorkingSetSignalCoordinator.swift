import AppleCore
@preconcurrency import FileProvider
import Foundation
import Network

final class IronmeshWorkingSetSignalCoordinator: @unchecked Sendable {
    private let configuration: IronmeshBundleConfiguration
    private let profileStore: AppleSyncProfileStore
    private let environment: any IronmeshSyncEnvironmentObserving
    private let domainManager: any AppleFileProviderDomainManaging
    private let lock = NSLock()
    private var observerToken: UUID?
    private var isActive = false

    init(
        configuration: IronmeshBundleConfiguration,
        profileStore: AppleSyncProfileStore? = nil,
        environment: any IronmeshSyncEnvironmentObserving = IronmeshLiveSyncEnvironment.shared,
        domainManager: any AppleFileProviderDomainManaging = AppleLiveFileProviderDomainManager()
    ) {
        self.configuration = configuration
        self.profileStore = profileStore ?? configuration.makeProfileStore()
        self.environment = environment
        self.domainManager = domainManager
    }

    deinit {
        invalidate()
    }

    func start() {
        lock.lock()
        guard !isActive else {
            lock.unlock()
            return
        }
        isActive = true
        lock.unlock()

        let token = environment.addChangeObserver { [weak self] previous, current in
            self?.environmentDidChange(from: previous, to: current)
        }
        lock.lock()
        if isActive {
            observerToken = token
            lock.unlock()
        } else {
            lock.unlock()
            environment.removeChangeObserver(token)
        }
    }

    func invalidate() {
        lock.lock()
        isActive = false
        let token = observerToken
        observerToken = nil
        lock.unlock()
        if let token {
            environment.removeChangeObserver(token)
        }
    }

    func signalIfConflictCopyWasCreated(_ error: Error) {
        guard AppleWorkingSetSignalPolicy.shouldSignal(after: error as NSError) else {
            return
        }
        signalBestEffort()
    }

    private func environmentDidChange(
        from previous: AppleSyncEnvironmentSnapshot,
        to current: AppleSyncEnvironmentSnapshot
    ) {
        guard activeSnapshot() else {
            return
        }
        let storedProfile = try? profileStore.profile(
            domainIdentifier: configuration.domainIdentifier
        )
        guard let profile = try? AppleSyncProfileResolution.resolve(
            domainIdentifier: configuration.domainIdentifier,
            storedProfile: storedProfile,
            configuredProfile: configuration.syncProfile,
            legacyDisplayName: configuration.domainDisplayName
        ), AppleSyncRecoverySignalPolicy.shouldSignal(
            profile: profile,
            previous: previous,
            current: current
        ) else {
            return
        }
        signalBestEffort()
    }

    private func signalBestEffort() {
        guard activeSnapshot() else {
            return
        }
        Task { [weak self] in
            guard let self, self.activeSnapshot() else {
                return
            }
            try? await self.domainManager.signalChanges(
                identifier: self.configuration.domainIdentifier,
                displayName: self.configuration.domainDisplayName
            )
        }
    }

    private func activeSnapshot() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return isActive
    }
}
