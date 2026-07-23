import AppleCore
import Combine
import FileProvider
import Foundation

extension IronmeshConnectionDraft {
    init(bundleConfiguration: IronmeshBundleConfiguration) {
        self.init(
            directConnectionInput: bundleConfiguration.connectionInput,
            domainIdentifier: bundleConfiguration.domainIdentifier,
            domainDisplayName: bundleConfiguration.domainDisplayName
        )
    }

    init(bundleConfiguration: IronmeshBundleConfiguration, storedState: AppleStoredConnectionState) {
        self.init(
            deviceLabel: storedState.deviceLabel ?? "",
            directConnectionInput: storedState.connectionInput ?? bundleConfiguration.connectionInput,
            bootstrapInput: storedState.bootstrapInputDraft ?? "",
            serverCAPem: storedState.serverCAPem ?? "",
            clientIdentityJSON: storedState.clientIdentityJSON ?? "",
            enrolledDeviceID: storedState.deviceID ?? "",
            domainIdentifier: bundleConfiguration.domainIdentifier,
            domainDisplayName: bundleConfiguration.domainDisplayName
        )
    }
}

typealias IronmeshDomainRegistrationState = AppleFileProviderDomainRegistrationState

struct IronmeshRecentAction: Equatable, Identifiable, Sendable {
    let title: String
    let detail: String
    let timestamp: Date

    var id: String {
        "\(timestamp.timeIntervalSince1970)-\(title)-\(detail)"
    }
}

struct IronmeshLibraryBreadcrumb: Equatable, Identifiable, Sendable {
    let path: String
    let label: String

    var id: String {
        path.isEmpty ? "/" : path
    }
}

enum IronmeshPreviewPayload: Equatable, Sendable {
    case text(String)
    case image(Data)
    case binary(String)
}

struct IronmeshFilePreviewResult: Equatable, Sendable {
    let filename: String
    let byteCount: Int
    let payload: IronmeshPreviewPayload
}

struct IronmeshConnectionAttemptStatus: Codable, Equatable, Identifiable, Sendable {
    var sourceLabel: String?
    var endpointLocator: String
    var pathKind: String
    var startedUnixMs: UInt64
    var finishedUnixMs: UInt64?
    var method: String
    var url: String
    var timeoutMs: UInt64?
    var outcome: String
    var error: String?

    var id: String {
        "\(endpointLocator)-\(startedUnixMs)-\(method)-\(url)"
    }
}

struct IronmeshConnectionEndpointStatus: Codable, Equatable, Identifiable, Sendable {
    var pathKind: String
    var locator: String
    var requestBaseUrl: String
    var active: Bool
    var consecutiveFailures: UInt32
    var totalFailures: UInt64
    var totalSuccesses: UInt64
    var lastAttemptUnixMs: UInt64?
    var lastSuccessUnixMs: UInt64?
    var lastFailureUnixMs: UInt64?
    var lastError: String?
    var recentAttempts: [IronmeshConnectionAttemptStatus]

    var id: String {
        "\(pathKind)-\(locator)-\(requestBaseUrl)"
    }
}

struct IronmeshConnectionDiagnosticsSnapshot: Codable, Equatable, Sendable {
    var connectionName: String?
    var endpoints: [IronmeshConnectionEndpointStatus]
    var lastSuccessUnixMs: UInt64?
}

struct IronmeshWebUIPresentation: Identifiable, Equatable, Sendable {
    let session: AppleWebUiSession

    var id: String {
        session.url.absoluteString
    }
}

@MainActor
final class IronmeshBrowserModel: ObservableObject {
    @Published var draft: IronmeshConnectionDraft {
        didSet {
            if oldValue.connectionConfiguration != draft.connectionConfiguration {
                invalidateConnectionRouteState()
            }
            persistDraft()
        }
    }

    @Published var hasCompletedOnboarding: Bool {
        didSet {
            userDefaults.set(hasCompletedOnboarding, forKey: onboardingStorageKey)
        }
    }

    @Published var items: [AppleBridgeItem] = []
    @Published var currentPath = ""
    @Published var currentItems: [AppleBridgeItem] = []
    @Published var statusText: String
    @Published var domainState: IronmeshDomainRegistrationState = .unchecked
    @Published var syncProfiles: [AppleSyncProfile] = []
    @Published var registeredSyncProfileDomains: [String: AppleRegisteredFileProviderDomain] = [:]
    @Published var syncProfilesErrorMessage: String?
    @Published private(set) var syncProfileOperationState = AppleSyncProfileOperationState()
    @Published var isBusy = false
    @Published var lastSuccessfulConnectionAt: Date?
    @Published var lastErrorMessage: String?
    @Published var recentActions: [IronmeshRecentAction] = []
    @Published var lastLibraryRefreshAt: Date?
    @Published var filesSelectionSummary: String?
    @Published var connectionDiagnostics: IronmeshConnectionDiagnosticsSnapshot?
    @Published var connectionRouteSnapshot: AppleConnectionRouteSnapshot?
    @Published var connectionRoutesErrorMessage: String?
    @Published var isRefreshingConnectionRoutes = false
    @Published var webUIPresentation: IronmeshWebUIPresentation?

    let bundleDefaults: IronmeshConnectionDraft

    private let remoteSession: IronmeshRemoteSession
    private let settingsStore: AppleConnectionSettingsStore
    private let enroller: AppleBootstrapEnroller
    private let fileProviderDomains: AppleFileProviderDomainCoordinator
    private let syncProfileDomains: AppleSyncProfileDomainCoordinator
    private let syncProfileStore: AppleSyncProfileStore
    private let userDefaults: UserDefaults
    private let draftStorageKey = AppleConnectionSettingsStore.defaultLegacyDraftStateKey
    private let onboardingStorageKey = "IronmeshIosApp.hasCompletedOnboarding"
    private let recentActionLimit = 6

    private var didActivate = false
    private var pendingOperations = 0
    private var connectionRouteRequests = AppleLatestRequestCoordinator()
    private var directoryLoadCoordinator = AppleDirectoryLoadCoordinator()

    var isSyncProfileMutationInProgress: Bool {
        syncProfileOperationState.isMutationInProgress
    }

    init(
        userDefaults: UserDefaults = .standard,
        settingsStore: AppleConnectionSettingsStore? = nil,
        enroller: AppleBootstrapEnroller = IronmeshRustFFIAdapter(connectionName: "ios app shell"),
        fileProviderDomains: AppleFileProviderDomainCoordinator = AppleFileProviderDomainCoordinator(),
        syncProfileDomains: AppleSyncProfileDomainCoordinator = AppleSyncProfileDomainCoordinator(),
        syncProfileStore: AppleSyncProfileStore? = nil,
        remoteSession: IronmeshRemoteSession = IronmeshRemoteSession()
    ) {
        self.userDefaults = userDefaults
        self.enroller = enroller
        self.remoteSession = remoteSession
        self.fileProviderDomains = fileProviderDomains
        self.syncProfileDomains = syncProfileDomains
        let bundleConfiguration = IronmeshBundleConfiguration(bundle: .main)
        let defaults = IronmeshConnectionDraft(bundleConfiguration: bundleConfiguration)
        bundleDefaults = defaults
        self.settingsStore = settingsStore ?? bundleConfiguration.makeSettingsStore()
        self.syncProfileStore = syncProfileStore ?? bundleConfiguration.makeProfileStore()

        let storedDraft: IronmeshConnectionDraft? = if let storedData = userDefaults.data(
            forKey: draftStorageKey
        ) {
            try? JSONDecoder().decode(IronmeshConnectionDraft.self, from: storedData)
        } else {
            nil
        }
        let storedState: AppleStoredConnectionState?
        let settingsLoadError: Error?
        do {
            storedState = try self.settingsStore.load(legacyDraftDefaults: userDefaults)
            settingsLoadError = nil
        } catch {
            storedState = nil
            settingsLoadError = error
        }

        let initialDraft: IronmeshConnectionDraft
        if var storedDraft {
            if let clientIdentity = storedState?.clientIdentityJSON?.nilIfBlank {
                storedDraft.clientIdentityJSON = clientIdentity
            }
            initialDraft = storedDraft
        } else if let storedState {
            initialDraft = IronmeshConnectionDraft(
                bundleConfiguration: bundleConfiguration,
                storedState: storedState
            )
        } else {
            initialDraft = defaults
        }
        draft = initialDraft

        hasCompletedOnboarding = userDefaults.object(forKey: onboardingStorageKey) as? Bool ?? false
        lastErrorMessage = settingsLoadError?.localizedDescription
        statusText = settingsLoadError?.localizedDescription ?? initialDraft.setupSummary
        do {
            syncProfiles = try self.syncProfileStore.load()
        } catch {
            syncProfilesErrorMessage = error.localizedDescription
        }
    }

    var shouldShowOnboarding: Bool {
        !hasCompletedOnboarding
    }

    var healthHeadline: String {
        if !draft.isConfigured {
            return "Finish setup"
        }
        if isBusy && lastSuccessfulConnectionAt == nil {
            return "Connecting to IronMesh"
        }
        if let lastErrorMessage, lastSuccessfulConnectionAt == nil, !lastErrorMessage.isEmpty {
            return "Connection needs attention"
        }
        if lastErrorMessage != nil {
            return "Connected with warnings"
        }
        if lastSuccessfulConnectionAt != nil {
            return "Connection healthy"
        }
        return "Ready to browse"
    }

    var healthSummary: String {
        if let lastErrorMessage, !lastErrorMessage.isEmpty {
            return lastErrorMessage
        }
        return draft.setupSummary
    }

    var rootDirectoryCount: Int {
        items.filter { $0.kind == .directory }.count
    }

    var rootFileCount: Int {
        items.filter { $0.kind == .file }.count
    }

    var libraryDirectories: [AppleBridgeItem] {
        sortedItems(currentItems.filter { $0.kind == .directory })
    }

    var libraryFiles: [AppleBridgeItem] {
        sortedItems(currentItems.filter { $0.kind == .file })
    }

    var breadcrumbs: [IronmeshLibraryBreadcrumb] {
        let components = normalizedPath(currentPath).split(separator: "/").map(String.init)
        guard !components.isEmpty else {
            return []
        }

        var segments: [String] = []
        return components.map { component in
            segments.append(component)
            return IronmeshLibraryBreadcrumb(path: segments.joined(separator: "/"), label: component)
        }
    }

    var filesIntegrationNote: String {
        "Each profile is a native Files domain backed by the shared enrolled device connection. iOS queues local work, materializes files on demand, and requests remote changes through persistent File Provider anchors without a foreground polling loop."
    }

    var orderedConnectionEndpoints: [IronmeshConnectionEndpointStatus] {
        (connectionDiagnostics?.endpoints ?? []).sorted { lhs, rhs in
            if lhs.active != rhs.active {
                return lhs.active && !rhs.active
            }
            if lhs.lastAttemptUnixMs != rhs.lastAttemptUnixMs {
                return (lhs.lastAttemptUnixMs ?? 0) > (rhs.lastAttemptUnixMs ?? 0)
            }
            return lhs.locator.localizedCaseInsensitiveCompare(rhs.locator) == .orderedAscending
        }
    }

    var recentConnectionAttempts: [IronmeshConnectionAttemptStatus] {
        orderedConnectionEndpoints
            .flatMap(\.recentAttempts)
            .sorted { $0.startedUnixMs > $1.startedUnixMs }
    }

    func activate() {
        guard !didActivate else {
            return
        }

        didActivate = true
        refreshDomainState()
        reconcileSyncProfileDomains()

        if draft.requiresEnrollment {
            hasCompletedOnboarding = false
            statusText = "Enroll this device to continue using the bootstrap bundle."
            lastErrorMessage = nil
            return
        }

        if hasCompletedOnboarding {
            refresh()
        } else {
            statusText = "Finish onboarding to start browsing the remote library."
        }
    }

    func completeOnboarding() {
        guard draft.isConfigured else {
            let message = "A bootstrap bundle or direct route is required."
            lastErrorMessage = message
            statusText = message
            addAction("Onboarding blocked", detail: message)
            return
        }

        if draft.requiresEnrollment {
            let message = "Enroll this device before continuing with a bootstrap bundle."
            hasCompletedOnboarding = false
            lastErrorMessage = message
            statusText = message
            addAction("Onboarding blocked", detail: message)
            return
        }

        do {
            try syncSharedSettingsFromDraft()
        } catch {
            lastErrorMessage = error.localizedDescription
            statusText = error.localizedDescription
            addAction("Onboarding blocked", detail: error.localizedDescription)
            return
        }

        hasCompletedOnboarding = true
        lastErrorMessage = nil
        invalidateConnectionRouteState()
        statusText = "Onboarding complete. Connecting to \(draft.normalizedConnectionInput ?? draft.effectiveConnectionInput)."
        addAction("Completed onboarding", detail: draft.enrollmentSummary)
        refreshDomainState()
        reloadRootAfterConnectionContextChange(actionTitle: "Loaded root after onboarding")
    }

    func applyConnectionSettings() {
        guard draft.isConfigured else {
            let message = "A bootstrap bundle or direct route is required."
            lastErrorMessage = message
            statusText = message
            addAction("Settings blocked", detail: message)
            return
        }

        if draft.requiresEnrollment {
            let message = "Enroll this device before reconnecting with a bootstrap bundle."
            hasCompletedOnboarding = false
            lastErrorMessage = message
            statusText = message
            addAction("Settings blocked", detail: message)
            return
        }

        do {
            try syncSharedSettingsFromDraft()
        } catch {
            lastErrorMessage = error.localizedDescription
            statusText = error.localizedDescription
            addAction("Settings blocked", detail: error.localizedDescription)
            return
        }

        lastErrorMessage = nil
        invalidateConnectionRouteState()
        statusText = "Applied connection settings. Reconnecting to \(draft.normalizedConnectionInput ?? draft.effectiveConnectionInput)."
        addAction("Applied settings", detail: draft.setupSummary)
        refreshDomainState()
        reloadRootAfterConnectionContextChange(actionTitle: "Loaded root after reconnecting")
    }

    func refresh() {
        let presentsRootDirectory = currentPath.isEmpty
        loadDirectory(
            path: "",
            updatesCurrentDirectory: presentsRootDirectory,
            updatesCurrentPath: presentsRootDirectory,
            actionTitle: "Refreshed root"
        )
    }

    func browse(path: String) {
        loadDirectory(
            path: path,
            updatesCurrentDirectory: true,
            updatesCurrentPath: true,
            actionTitle: "Opened \(displayPath(path))"
        )
    }

    func navigateUp() {
        let normalized = normalizedPath(currentPath)
        guard let slashIndex = normalized.lastIndex(of: "/") else {
            browse(path: "")
            return
        }

        browse(path: String(normalized[..<slashIndex]))
    }

    func refreshCurrentDirectory() {
        loadDirectory(
            path: currentPath,
            updatesCurrentDirectory: true,
            updatesCurrentPath: false,
            actionTitle: "Refreshed \(displayPath(currentPath))"
        )
    }

    func registerDomain() {
        let identifier = draft.domainIdentifier.nilIfBlank ?? bundleDefaults.domainIdentifier
        let displayName = draft.domainDisplayName.nilIfBlank ?? bundleDefaults.domainDisplayName

        beginOperation()
        Task {
            let result = await fileProviderDomains.register(
                identifier: identifier,
                displayName: displayName
            )

            defer { self.endOperation() }

            self.domainState = result.state
            switch result.state {
            case .registered:
                self.lastErrorMessage = nil
                if result.wasCreated {
                    self.statusText = "Registered File Provider domain \(identifier)."
                    self.addAction("Registered File Provider domain", detail: identifier)
                } else {
                    self.statusText = "File Provider domain \(identifier) is already registered."
                    self.addAction("Confirmed File Provider domain", detail: identifier)
                }
            case .failed(let message):
                self.lastErrorMessage = message
                self.statusText = message
                self.addAction("Domain registration failed", detail: message)
            case .unchecked, .checking, .missing:
                break
            }
        }
    }

    func refreshDomainState() {
        let expectedIdentifier = draft.domainIdentifier.nilIfBlank ?? bundleDefaults.domainIdentifier
        domainState = .checking

        Task {
            self.domainState = await fileProviderDomains.refresh(
                expectedIdentifier: expectedIdentifier
            )
        }
    }

    @discardableResult
    func configureSyncProfile(
        displayName: String,
        remotePrefix: String,
        depth: Int,
        allowsExpensiveNetwork: Bool,
        allowsConstrainedNetwork: Bool,
        defersInLowPowerMode: Bool
    ) -> Bool {
        guard draft.connectionConfiguration != nil, !draft.requiresEnrollment else {
            let message = "Apply and enroll the shared device connection before adding a sync profile."
            syncProfilesErrorMessage = message
            statusText = message
            return false
        }
        guard displayName.nilIfBlank != nil else {
            let message = "A sync profile needs a display name."
            syncProfilesErrorMessage = message
            statusText = message
            return false
        }

        let profile = AppleSyncProfile(
            displayName: displayName,
            remotePrefix: remotePrefix,
            depth: depth,
            networkPolicy: AppleSyncProfileNetworkPolicy(
                allowsExpensiveNetwork: allowsExpensiveNetwork,
                allowsConstrainedNetwork: allowsConstrainedNetwork
            ),
            powerPolicy: AppleSyncProfilePowerPolicy(
                defersInLowPowerMode: defersInLowPowerMode
            )
        )

        guard beginSyncProfileMutation() else {
            return false
        }

        do {
            syncProfiles = try syncProfileStore.upsert(profile)
        } catch {
            endSyncProfileMutation()
            syncProfilesErrorMessage = error.localizedDescription
            statusText = error.localizedDescription
            return false
        }

        Task {
            defer { endSyncProfileMutation() }
            do {
                try await syncProfileDomains.configure(profile)
                try await refreshSyncProfileDomainsThrowing()
                syncProfilesErrorMessage = nil
                statusText = "Added Files sync profile \(profile.displayName)."
                addAction("Added sync profile", detail: "\(profile.displayName): \(profile.scopeSummary)")
            } catch {
                syncProfilesErrorMessage = error.localizedDescription
                statusText = error.localizedDescription
                addAction("Sync profile registration failed", detail: error.localizedDescription)
            }
        }
        return true
    }

    func pauseSyncProfile(_ profile: AppleSyncProfile) {
        updateSyncProfileLifecycle(profile, lifecycle: .paused)
    }

    func resumeSyncProfile(_ profile: AppleSyncProfile) {
        updateSyncProfileLifecycle(profile, lifecycle: .active)
    }

    func removeSyncProfile(_ profile: AppleSyncProfile) {
        guard beginSyncProfileMutation() else {
            return
        }
        Task {
            defer { endSyncProfileMutation() }
            do {
                try await syncProfileDomains.remove(profile)
                syncProfiles = try syncProfileStore.remove(profileID: profile.id)
                registeredSyncProfileDomains.removeValue(forKey: profile.domainIdentifier)
                syncProfilesErrorMessage = nil
                statusText = "Removed Files sync profile \(profile.displayName)."
                addAction("Removed sync profile", detail: profile.displayName)
            } catch {
                syncProfilesErrorMessage = error.localizedDescription
                statusText = error.localizedDescription
                addAction("Sync profile removal failed", detail: error.localizedDescription)
            }
        }
    }

    func requestSyncProfileRefresh(_ profile: AppleSyncProfile) {
        beginOperation()
        Task {
            defer { endOperation() }
            do {
                try await syncProfileDomains.signalChanges(profile)
                syncProfilesErrorMessage = nil
                statusText = "Asked Files to discover remote changes for \(profile.displayName)."
                addAction("Requested remote discovery", detail: profile.displayName)
            } catch {
                syncProfilesErrorMessage = error.localizedDescription
                statusText = error.localizedDescription
            }
        }
    }

    func refreshSyncProfileDomains() {
        beginOperation()
        Task {
            defer { endOperation() }
            do {
                try await refreshSyncProfileDomainsThrowing()
                syncProfilesErrorMessage = nil
            } catch {
                syncProfilesErrorMessage = error.localizedDescription
            }
        }
    }

    func registeredDomain(for profile: AppleSyncProfile) -> AppleRegisteredFileProviderDomain? {
        registeredSyncProfileDomains[profile.domainIdentifier]
    }

    private func reconcileSyncProfileDomains() {
        guard beginSyncProfileMutation() else {
            return
        }
        Task {
            defer { endSyncProfileMutation() }
            do {
                let reconciliationErrors = await syncProfileDomains.reconcile(syncProfiles)
                try await refreshSyncProfileDomainsThrowing()
                syncProfilesErrorMessage = reconciliationErrors.isEmpty
                    ? nil
                    : reconciliationErrors.joined(separator: "\n")
            } catch {
                syncProfilesErrorMessage = error.localizedDescription
            }
        }
    }

    private func updateSyncProfileLifecycle(
        _ profile: AppleSyncProfile,
        lifecycle: AppleSyncProfileLifecycle
    ) {
        guard beginSyncProfileMutation() else {
            return
        }
        Task {
            defer { endSyncProfileMutation() }
            do {
                syncProfiles = try syncProfileStore.setLifecycle(
                    lifecycle,
                    profileID: profile.id
                )
                var updatedProfile = profile
                updatedProfile.lifecycle = lifecycle
                do {
                    if lifecycle == .paused {
                        try await syncProfileDomains.pause(updatedProfile)
                    } else {
                        try await syncProfileDomains.resume(updatedProfile)
                    }
                } catch {
                    // On macOS the domain-level disconnect/reconnect can fail. Restore the
                    // persisted gate so app and extension still agree on the lifecycle.
                    #if os(macOS)
                    syncProfiles = try syncProfileStore.setLifecycle(
                        profile.lifecycle,
                        profileID: profile.id
                    )
                    #endif
                    throw error
                }
                try await refreshSyncProfileDomainsThrowing()
                syncProfilesErrorMessage = nil
                statusText = lifecycle == .paused
                    ? "Paused \(profile.displayName). Existing downloaded files remain available."
                    : "Resumed \(profile.displayName). Files will retry queued work."
                addAction(
                    lifecycle == .paused ? "Paused sync profile" : "Resumed sync profile",
                    detail: profile.displayName
                )
            } catch {
                syncProfilesErrorMessage = error.localizedDescription
                statusText = error.localizedDescription
            }
        }
    }

    private func refreshSyncProfileDomainsThrowing() async throws {
        registeredSyncProfileDomains = try await syncProfileDomains.registeredProfiles(syncProfiles)
    }

    private func beginSyncProfileMutation() -> Bool {
        guard syncProfileOperationState.beginMutation() else {
            let message = "Wait for the current sync profile operation to finish."
            syncProfilesErrorMessage = message
            statusText = message
            return false
        }
        beginOperation()
        return true
    }

    private func endSyncProfileMutation() {
        syncProfileOperationState.endMutation()
        endOperation()
    }

    func resetToBundleDefaults() {
        closeWebUI()
        do {
            try settingsStore.save(
                bundleDefaults.appliedConnectionState(
                    defaultConnectionInput: bundleDefaults.directConnectionInput
                )
            )
        } catch {
            lastErrorMessage = error.localizedDescription
            statusText = error.localizedDescription
            addAction("Restore defaults failed", detail: error.localizedDescription)
            return
        }
        draft = bundleDefaults
        invalidateConnectionRouteState()
        lastErrorMessage = nil
        statusText = "Restored bundled defaults."
        addAction("Restored defaults", detail: draft.setupSummary)
        refreshDomainState()
        if hasCompletedOnboarding, !draft.requiresEnrollment, draft.connectionConfiguration != nil {
            reloadRootAfterConnectionContextChange(actionTitle: "Loaded bundled root")
        } else {
            clearDirectoryAfterConnectionContextChange()
        }
    }

    func clearAppSetup() {
        closeWebUI()
        do {
            try settingsStore.clear()
        } catch {
            lastErrorMessage = error.localizedDescription
            statusText = error.localizedDescription
            addAction("Clear setup failed", detail: error.localizedDescription)
            return
        }
        draft = IronmeshConnectionDraft(
            deviceLabel: draft.deviceLabel,
            domainIdentifier: bundleDefaults.domainIdentifier,
            domainDisplayName: bundleDefaults.domainDisplayName
        )
        hasCompletedOnboarding = false
        clearDirectoryAfterConnectionContextChange()
        lastSuccessfulConnectionAt = nil
        lastErrorMessage = nil
        connectionDiagnostics = nil
        invalidateConnectionRouteState()
        webUIPresentation = nil
        statusText = "Setup cleared. Finish onboarding to reconnect."
        addAction("Cleared setup", detail: "App connection and identity fields were reset.")
    }

    func clearIdentity() {
        closeWebUI()
        var clearedDraft = draft
        clearedDraft.clientIdentityJSON = ""
        clearedDraft.serverCAPem = ""
        clearedDraft.enrolledDeviceID = ""
        do {
            try settingsStore.save(
                clearedDraft.appliedConnectionState(
                    defaultConnectionInput: bundleDefaults.directConnectionInput
                )
            )
        } catch {
            lastErrorMessage = error.localizedDescription
            statusText = error.localizedDescription
            addAction("Clear identity failed", detail: error.localizedDescription)
            return
        }
        draft = clearedDraft
        if clearedDraft.requiresEnrollment {
            hasCompletedOnboarding = false
        }
        invalidateConnectionRouteState()
        clearDirectoryAfterConnectionContextChange()
        addAction("Cleared identity material", detail: "Removed client identity JSON and custom CA.")
    }

    func applyScannedCode(_ scannedValue: String) {
        if draft.applyScannedCode(scannedValue) {
            lastErrorMessage = nil
            statusText = "Imported scanned connection payload."
            addAction("Imported QR payload", detail: draft.hasBootstrapPayload ? "Bootstrap bundle" : "Direct route")
            return
        }

        let message = "The scanned code did not contain a usable bootstrap or route."
        lastErrorMessage = message
        statusText = message
        addAction("Ignored QR payload", detail: message)
    }

    func item(at path: String?) -> AppleBridgeItem? {
        guard let path else {
            return nil
        }

        return currentItems.first(where: { $0.path == path }) ?? items.first(where: { $0.path == path })
    }

    func noteFilesSelection(_ url: URL) {
        filesSelectionSummary = url.lastPathComponent.nilIfBlank ?? url.path
        addAction("Visited Files handoff", detail: filesSelectionSummary ?? url.path)
    }

    func enrollDevice(completesOnboarding: Bool = false) {
        guard let bootstrapInput = draft.bootstrapInput.nilIfBlank else {
            let message = "Bootstrap claim or bundle is required."
            lastErrorMessage = message
            statusText = message
            addAction("Enrollment blocked", detail: message)
            return
        }

        let deviceID = draft.enrolledDeviceID.nilIfBlank
        let deviceLabel = draft.deviceLabel.nilIfBlank
        let remoteSession = remoteSession
        let enroller = enroller

        beginOperation()
        Task {
            defer { endOperation() }

            do {
                let enrollment = try await Task.detached(priority: .userInitiated) {
                    try enroller.enrollConnectionInput(
                        bootstrapInput,
                        deviceID: deviceID,
                        label: deviceLabel
                    )
                }.value

                var updatedDraft = draft
                updatedDraft.directConnectionInput = enrollment.connectionInput
                updatedDraft.bootstrapInput = ""
                updatedDraft.serverCAPem = enrollment.serverCAPem ?? updatedDraft.serverCAPem
                updatedDraft.clientIdentityJSON = enrollment.clientIdentityJSON
                updatedDraft.enrolledDeviceID = enrollment.deviceID
                updatedDraft.deviceLabel = enrollment.deviceLabel ?? updatedDraft.deviceLabel
                try settingsStore.save(
                    enrollment.storedState(serverCAPemFallback: updatedDraft.serverCAPem.nilIfBlank)
                )
                draft = updatedDraft
                invalidateConnectionRouteState()

                if let configuration = draft.connectionConfiguration {
                    connectionDiagnostics = try? remoteSession.connectionDiagnostics(configuration: configuration)
                }

                lastErrorMessage = nil
                statusText = "Device enrolled: \(enrollment.deviceID)"
                addAction("Enrolled device", detail: draft.deviceLabel.nilIfBlank ?? enrollment.deviceID)

                if completesOnboarding {
                    hasCompletedOnboarding = true
                    refreshDomainState()
                }
                reloadRootAfterConnectionContextChange(actionTitle: "Loaded root after enrollment")
            } catch {
                lastErrorMessage = error.localizedDescription
                statusText = error.localizedDescription
                addAction("Enrollment failed", detail: error.localizedDescription)
            }
        }
    }

    func refreshConnectionDiagnostics() {
        guard let configuration = draft.connectionConfiguration else {
            let message = "A bootstrap bundle or direct route is required."
            lastErrorMessage = message
            statusText = message
            return
        }

        let remoteSession = remoteSession
        beginOperation()
        Task {
            defer { endOperation() }

            do {
                let diagnostics = try await Task.detached(priority: .userInitiated) {
                    try remoteSession.connectionDiagnostics(configuration: configuration)
                }.value
                connectionDiagnostics = diagnostics
                lastErrorMessage = nil
                statusText = "Refreshed connection diagnostics for \(diagnostics.connectionName ?? "ios app shell")."
                addAction("Refreshed diagnostics", detail: "\(diagnostics.endpoints.count) endpoint(s)")
            } catch {
                lastErrorMessage = error.localizedDescription
                statusText = error.localizedDescription
                addAction("Diagnostics failed", detail: error.localizedDescription)
            }
        }
    }

    func refreshConnectionPaths() {
        guard let configuration = draft.connectionConfiguration else {
            invalidateConnectionRouteState()
            let message = "A bootstrap bundle or direct route is required."
            connectionRoutesErrorMessage = message
            statusText = message
            return
        }

        let remoteSession = remoteSession
        let requestToken = connectionRouteRequests.begin()
        isRefreshingConnectionRoutes = true
        beginOperation()
        Task {
            defer {
                if connectionRouteRequests.complete(requestToken) {
                    isRefreshingConnectionRoutes = false
                }
                endOperation()
            }

            do {
                let snapshot = try await Task.detached(priority: .userInitiated) {
                    try remoteSession.connectionRouteSnapshot(
                        configuration: configuration,
                        refresh: true
                    )
                }.value
                guard connectionRouteRequests.isCurrent(requestToken) else {
                    return
                }
                connectionRouteSnapshot = snapshot
                connectionRoutesErrorMessage = nil
                statusText = "Re-evaluated \(snapshot.endpoints.count) connection path(s)."
                addAction("Re-evaluated connection paths", detail: "\(snapshot.endpoints.count) path(s)")
            } catch {
                guard connectionRouteRequests.isCurrent(requestToken) else {
                    return
                }
                connectionRoutesErrorMessage = error.localizedDescription
                statusText = error.localizedDescription
                addAction("Connection paths failed", detail: error.localizedDescription)
            }
        }
    }

    func openWebUI() {
        guard let configuration = draft.connectionConfiguration else {
            let message = "A bootstrap bundle or direct route is required."
            lastErrorMessage = message
            statusText = message
            return
        }

        let remoteSession = remoteSession
        beginOperation()
        Task {
            defer { endOperation() }

            do {
                let session = try await Task.detached(priority: .userInitiated) {
                    try remoteSession.startWebUI(configuration: configuration)
                }.value
                webUIPresentation = IronmeshWebUIPresentation(session: session)
                lastErrorMessage = nil
                statusText = "Opened embedded web UI."
                addAction("Opened web UI", detail: "Started isolated loopback session.")
            } catch {
                lastErrorMessage = error.localizedDescription
                statusText = error.localizedDescription
                addAction("Web UI failed", detail: error.localizedDescription)
            }
        }
    }

    func closeWebUI() {
        webUIPresentation = nil
        do {
            try remoteSession.stopWebUI()
        } catch {
            lastErrorMessage = error.localizedDescription
        }
    }

    func loadPreview(for item: AppleBridgeItem) async -> IronmeshFilePreviewResult {
        guard draft.isConfigured else {
            return IronmeshFilePreviewResult(
                filename: item.displayName,
                byteCount: 0,
                payload: .binary("Configure a connection target before loading previews.")
            )
        }

        if item.kind == .directory {
            return IronmeshFilePreviewResult(
                filename: item.displayName,
                byteCount: 0,
                payload: .binary("Directory previews are not available.")
            )
        }

        if let sizeBytes = item.sizeBytes, sizeBytes > 1_500_000 {
            let formatter = ByteCountFormatter()
            formatter.countStyle = .file
            return IronmeshFilePreviewResult(
                filename: item.displayName,
                byteCount: Int(sizeBytes),
                payload: .binary("Preview skipped for large file (\(formatter.string(fromByteCount: sizeBytes))).")
            )
        }

        guard let configuration = draft.connectionConfiguration else {
            return IronmeshFilePreviewResult(
                filename: item.displayName,
                byteCount: 0,
                payload: .binary("No usable connection configuration found.")
            )
        }

        let remoteSession = remoteSession
        let path = item.path
        let revisionHint = item.revisionHint

        do {
            let data = try await Task.detached(priority: .userInitiated) {
                try remoteSession.download(
                    path: path,
                    revisionHint: revisionHint,
                    configuration: configuration
                )
            }.value

            if let previewText = previewText(from: data) {
                return IronmeshFilePreviewResult(
                    filename: item.displayName,
                    byteCount: data.count,
                    payload: .text(previewText)
                )
            }

            if previewLooksLikeImage(path: path, data: data) {
                return IronmeshFilePreviewResult(
                    filename: item.displayName,
                    byteCount: data.count,
                    payload: .image(data)
                )
            }

            let formatter = ByteCountFormatter()
            formatter.countStyle = .file
            return IronmeshFilePreviewResult(
                filename: item.displayName,
                byteCount: data.count,
                payload: .binary("Binary file loaded (\(formatter.string(fromByteCount: Int64(data.count)))).")
            )
        } catch {
            return IronmeshFilePreviewResult(
                filename: item.displayName,
                byteCount: 0,
                payload: .binary(error.localizedDescription)
            )
        }
    }

    private func loadDirectory(
        path: String,
        updatesCurrentDirectory: Bool,
        updatesCurrentPath: Bool,
        actionTitle: String
    ) {
        let request = directoryLoadCoordinator.begin(
            path: path,
            updatesCurrentDirectory: updatesCurrentDirectory,
            updatesCurrentPath: updatesCurrentPath
        )

        loadDirectory(request: request, actionTitle: actionTitle)
    }

    private func reloadRootAfterConnectionContextChange(actionTitle: String) {
        let request = directoryLoadCoordinator.beginConnectionContextReset()
        clearDirectoryPresentation()
        loadDirectory(request: request, actionTitle: actionTitle)
    }

    private func clearDirectoryAfterConnectionContextChange() {
        directoryLoadCoordinator.invalidate()
        clearDirectoryPresentation()
    }

    private func clearDirectoryPresentation() {
        items = []
        currentItems = []
        currentPath = ""
    }

    private func loadDirectory(request: AppleDirectoryLoadRequest, actionTitle: String) {
        guard let configuration = draft.connectionConfiguration else {
            let message = "A bootstrap bundle or direct route is required."
            lastErrorMessage = message
            statusText = message
            if directoryLoadCoordinator.acceptsCurrentDirectory(request), request.updatesCurrentPath {
                currentPath = request.path
                currentItems = []
            }
            return
        }

        let remoteSession = remoteSession
        beginOperation()

        Task {
            defer { endOperation() }

            do {
                let loadedItems = try await Task.detached(priority: .userInitiated) {
                    try remoteSession.list(path: request.path, configuration: configuration)
                }.value

                guard directoryLoadCoordinator.acceptsAnyResult(from: request) else {
                    return
                }

                if directoryLoadCoordinator.acceptsRootSnapshot(request) {
                    items = loadedItems
                }
                if directoryLoadCoordinator.acceptsCurrentDirectory(request) {
                    if request.updatesCurrentPath {
                        currentPath = request.path
                    }
                    currentItems = loadedItems
                }

                guard directoryLoadCoordinator.acceptsSharedState(request) else {
                    return
                }

                let diagnostics = try? remoteSession.connectionDiagnostics(configuration: configuration)
                guard directoryLoadCoordinator.acceptsSharedState(request) else {
                    return
                }

                let loadedAt = Date()
                lastLibraryRefreshAt = loadedAt
                lastSuccessfulConnectionAt = loadedAt
                connectionDiagnostics = diagnostics
                lastErrorMessage = nil
                statusText = "Loaded \(loadedItems.count) item(s) from \(displayPath(request.path))."
                addAction(actionTitle, detail: "Loaded \(loadedItems.count) item(s)")
            } catch {
                guard directoryLoadCoordinator.acceptsSharedState(request) else {
                    return
                }
                connectionDiagnostics = try? remoteSession.connectionDiagnostics(configuration: configuration)
                guard directoryLoadCoordinator.acceptsSharedState(request) else {
                    return
                }
                lastErrorMessage = error.localizedDescription
                statusText = error.localizedDescription
                addAction("Browse failed", detail: error.localizedDescription)
            }
        }
    }

    private func persistDraft() {
        guard let data = try? JSONEncoder().encode(draft) else {
            return
        }
        userDefaults.set(data, forKey: draftStorageKey)
    }

    private func syncSharedSettingsFromDraft() throws {
        try settingsStore.save(
            draft.appliedConnectionState(defaultConnectionInput: bundleDefaults.directConnectionInput)
        )
    }

    private func invalidateConnectionRouteState() {
        connectionRouteRequests.invalidate()
        connectionRouteSnapshot = nil
        connectionRoutesErrorMessage = nil
        isRefreshingConnectionRoutes = false
    }

    private func addAction(_ title: String, detail: String) {
        recentActions.insert(
            IronmeshRecentAction(title: title, detail: detail, timestamp: Date()),
            at: 0
        )
        if recentActions.count > recentActionLimit {
            recentActions.removeLast(recentActions.count - recentActionLimit)
        }
    }

    private func beginOperation() {
        pendingOperations += 1
        isBusy = pendingOperations > 0
    }

    private func endOperation() {
        pendingOperations = max(0, pendingOperations - 1)
        isBusy = pendingOperations > 0
    }
}

final class IronmeshRemoteSession: @unchecked Sendable {
    private let bridge: AppleCFacadeBridge
    private let lock = NSLock()
    private var configurationKey: String?

    init(ffi: AppleManualCBridgeFFI = IronmeshRustFFIAdapter(connectionName: "ios app shell")) {
        bridge = AppleCFacadeBridge(ffi: ffi)
    }

    func list(path: String, configuration: AppleConnectionConfiguration) throws -> [AppleBridgeItem] {
        try connectIfNeeded(configuration)
        return sortedItems(try bridge.list(path: path, depth: 1))
    }

    func download(
        path: String,
        revisionHint: String?,
        configuration: AppleConnectionConfiguration
    ) throws -> Data {
        try connectIfNeeded(configuration)
        return try bridge.download(path: path, revisionHint: revisionHint)
    }

    func connectionDiagnostics(
        configuration: AppleConnectionConfiguration
    ) throws -> IronmeshConnectionDiagnosticsSnapshot {
        try connectIfNeeded(configuration)
        let json = try bridge.connectionDiagnosticsJSON()
        return try decode(IronmeshConnectionDiagnosticsSnapshot.self, from: json)
    }

    func connectionRouteSnapshot(
        configuration: AppleConnectionConfiguration,
        refresh: Bool
    ) throws -> AppleConnectionRouteSnapshot {
        try connectIfNeeded(configuration)
        let json = try bridge.connectionRouteSnapshotJSON(refresh: refresh)
        return try decode(AppleConnectionRouteSnapshot.self, from: json)
    }

    func startWebUI(configuration: AppleConnectionConfiguration) throws -> AppleWebUiSession {
        try bridge.startWebUI(configuration: configuration)
    }

    func stopWebUI() throws {
        try bridge.stopWebUI()
    }

    private func connectIfNeeded(_ configuration: AppleConnectionConfiguration) throws {
        let nextKey = configuration.cacheKey

        lock.lock()
        let currentKey = configurationKey
        lock.unlock()

        guard currentKey != nextKey else {
            return
        }

        _ = try bridge.connect(configuration)

        lock.lock()
        configurationKey = nextKey
        lock.unlock()
    }

    private func decode<T: Decodable>(_ type: T.Type, from json: String) throws -> T {
        let data = Data(json.utf8)
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        do {
            return try decoder.decode(type, from: data)
        } catch {
            throw AppleManualCBridgeError.invalidResponse(error.localizedDescription)
        }
    }
}

func displayPath(_ path: String) -> String {
    let normalized = normalizedPath(path)
    return normalized.isEmpty ? "/" : "/\(normalized)"
}

private func sortedItems(_ items: [AppleBridgeItem]) -> [AppleBridgeItem] {
    items.sorted {
        if $0.kind != $1.kind {
            return $0.kind == .directory
        }
        return $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
    }
}

private func previewText(from data: Data) -> String? {
    guard !data.isEmpty else {
        return ""
    }

    guard let preview = String(data: data.prefix(8_192), encoding: .utf8) else {
        return nil
    }

    if preview.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        && !preview.contains("\n")
        && !preview.contains("\t") {
        return nil
    }

    return preview
}

private func previewLooksLikeImage(path: String, data: Data) -> Bool {
    let lowercased = path.lowercased()
    if [".png", ".jpg", ".jpeg", ".gif", ".heic", ".webp"].contains(where: lowercased.hasSuffix) {
        return true
    }

    return data.starts(with: [0x89, 0x50, 0x4E, 0x47])
        || data.starts(with: [0xFF, 0xD8, 0xFF])
        || data.starts(with: [0x47, 0x49, 0x46, 0x38])
}

private extension AppleConnectionConfiguration {
    var cacheKey: String {
        [
            normalizedConnectionInput,
            serverCAPem ?? "",
            clientIdentityJSON ?? "",
        ].joined(separator: "\n---\n")
    }
}
