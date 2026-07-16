import AppleCore
import FileProvider
import Foundation

@MainActor
final class IronmeshBrowserModel: ObservableObject {
    @Published var items: [AppleBridgeItem] = []
    @Published var statusText: String
    @Published var connectionInput: String
    @Published var bootstrapInput: String
    @Published var deviceLabelInput: String
    @Published var enrolledDeviceID: String?
    @Published var enrolledDeviceLabel: String?
    @Published var isBusy = false
    @Published var webUiBaseURL: URL?
    @Published var isStartingWebUi = false

    let service: IronmeshFileProviderService

    private let enroller: AppleBootstrapEnroller

    init(
        service: IronmeshFileProviderService = IronmeshFileProviderService(),
        enroller: AppleBootstrapEnroller = IronmeshRustFFIAdapter()
    ) {
        self.service = service
        self.enroller = enroller

        let storedState = service.storedConnectionState()
        let configuration = service.currentConnectionConfiguration()
        connectionInput = configuration.connectionInput
        bootstrapInput = storedState.bootstrapInputDraft ?? ""
        deviceLabelInput = storedState.deviceLabel ?? ""
        enrolledDeviceID = storedState.deviceID
        enrolledDeviceLabel = storedState.deviceLabel
        statusText = Self.summaryText(
            configuration: configuration,
            deviceID: storedState.deviceID,
            status: nil
        )
    }

    var hasEnrolledDevice: Bool {
        enrolledDeviceID?.nilIfBlank != nil
    }

    var galleryMapURL: URL? {
        guard let webUiBaseURL else {
            return nil
        }

        var components = URLComponents(url: webUiBaseURL, resolvingAgainstBaseURL: false)
        var queryItems = components?.queryItems ?? []
        queryItems.removeAll { $0.name == "embedded" }
        queryItems.append(URLQueryItem(name: "embedded", value: "gallery_map"))
        components?.queryItems = queryItems
        return components?.url ?? webUiBaseURL
    }

    func refresh() {
        let configuration = service.currentConnectionConfiguration()
        runBusyTask(loadingStatus: "Loading root items from \(configuration.connectionInput)") {
            let items = try self.service.list(path: "")
            return (items, configuration)
        } onSuccess: { items, configuration in
            self.items = items
            self.connectionInput = configuration.connectionInput
            self.statusText = Self.summaryText(
                configuration: configuration,
                deviceID: self.enrolledDeviceID,
                status: "Loaded \(items.count) root item(s)"
            )
        }
    }

    func registerDomain() {
        isBusy = true
        service.registerDomain { error in
            Task { @MainActor in
                self.isBusy = false
                if let error {
                    self.statusText = error.localizedDescription
                } else {
                    self.statusText = "Registered File Provider domain \(self.service.configuration.domainIdentifier)"
                }
            }
        }
    }

    func saveConnectionInput() {
        let trimmed = connectionInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            statusText = "Connection input must not be empty."
            return
        }

        do {
            var state = service.storedConnectionState()
            state.connectionInput = trimmed
            state.deviceLabel = deviceLabelInput.nilIfBlank
            state.bootstrapInputDraft = bootstrapInput.nilIfBlank
            try service.saveConnectionState(state)

            let configuration = service.currentConnectionConfiguration()
            connectionInput = configuration.connectionInput
            syncStoredState()
            invalidateGalleryMap()
            statusText = Self.summaryText(
                configuration: configuration,
                deviceID: enrolledDeviceID,
                status: "Saved connection settings"
            )
        } catch {
            statusText = error.localizedDescription
        }
    }

    func updateBootstrapInput(_ value: String) {
        bootstrapInput = value
        persistDraftState()
    }

    func updateDeviceLabelInput(_ value: String) {
        deviceLabelInput = value
        persistDraftState()
    }

    func enrollDevice() {
        let trimmedBootstrap = bootstrapInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedBootstrap.isEmpty else {
            statusText = "Bootstrap claim or bundle is required."
            return
        }

        let currentState = service.storedConnectionState().withBootstrapDraft(trimmedBootstrap)
        let fallbackConnectionInput = service.currentConnectionConfiguration().connectionInput
        let deviceLabel = deviceLabelInput.nilIfBlank

        runBusyTask(loadingStatus: "Enrolling device...") {
            let enrollment = try self.enroller.enrollConnectionInput(
                trimmedBootstrap,
                deviceID: currentState.deviceID,
                label: deviceLabel
            )
            let updatedState = try enrollment.applying(
                to: currentState,
                fallbackConnectionInput: fallbackConnectionInput
            )
            try self.service.saveConnectionState(updatedState)
            let items = try self.service.list(path: "")
            return (enrollment, updatedState, items)
        } onSuccess: { enrollment, updatedState, items in
            self.items = items
            self.connectionInput = updatedState.connectionInput ?? fallbackConnectionInput
            self.bootstrapInput = ""
            self.deviceLabelInput = updatedState.deviceLabel ?? ""
            self.enrolledDeviceID = updatedState.deviceID
            self.enrolledDeviceLabel = updatedState.deviceLabel
            self.invalidateGalleryMap()
            self.statusText = Self.summaryText(
                configuration: self.service.currentConnectionConfiguration(),
                deviceID: updatedState.deviceID,
                status: "Device enrolled: \(enrollment.deviceID)"
            )
        }
    }

    func clearDeviceEnrollment() {
        do {
            var state = service.storedConnectionState().clearingEnrollment()
            state.bootstrapInputDraft = bootstrapInput.nilIfBlank
            try service.saveConnectionState(state)
            syncStoredState()
            invalidateGalleryMap()
            statusText = Self.summaryText(
                configuration: service.currentConnectionConfiguration(),
                deviceID: nil,
                status: "Cleared local device identity"
            )
        } catch {
            statusText = error.localizedDescription
        }
    }

    func startGalleryMap(force: Bool = false) {
        let configuration = service.currentConnectionConfiguration()
        guard !configuration.normalizedConnectionInput.isEmpty,
              configuration.clientIdentityJSON?.nilIfBlank != nil else {
            invalidateGalleryMap()
            statusText = "Enroll this device before opening the gallery map."
            return
        }
        if isStartingWebUi || (!force && webUiBaseURL != nil) {
            return
        }

        isStartingWebUi = true
        if force {
            webUiBaseURL = nil
        }
        statusText = "Starting gallery map..."
        let service = self.service
        Task.detached(priority: .userInitiated) {
            do {
                let url = try service.startWebUi()
                await MainActor.run {
                    self.isStartingWebUi = false
                    self.webUiBaseURL = url
                    self.statusText = "Gallery map ready at \(url.absoluteString)"
                }
            } catch {
                await MainActor.run {
                    self.isStartingWebUi = false
                    self.webUiBaseURL = nil
                    self.statusText = error.localizedDescription
                }
            }
        }
    }

    private func syncStoredState() {
        let storedState = service.storedConnectionState()
        connectionInput = service.currentConnectionConfiguration().connectionInput
        bootstrapInput = storedState.bootstrapInputDraft ?? ""
        deviceLabelInput = storedState.deviceLabel ?? ""
        enrolledDeviceID = storedState.deviceID
        enrolledDeviceLabel = storedState.deviceLabel
    }

    private func persistDraftState() {
        do {
            var state = service.storedConnectionState()
            state.bootstrapInputDraft = bootstrapInput.nilIfBlank
            state.deviceLabel = deviceLabelInput.nilIfBlank
            try service.saveConnectionState(state, reconnect: false)
        } catch {
            statusText = error.localizedDescription
        }
    }

    private func invalidateGalleryMap() {
        webUiBaseURL = nil
    }

    private func runBusyTask<Output>(
        loadingStatus: String,
        operation: @escaping @Sendable () throws -> Output,
        onSuccess: @escaping @MainActor (Output) -> Void
    ) {
        isBusy = true
        statusText = loadingStatus
        Task.detached(priority: .userInitiated) {
            do {
                let output = try operation()
                await MainActor.run {
                    self.isBusy = false
                    onSuccess(output)
                }
            } catch {
                await MainActor.run {
                    self.isBusy = false
                    self.statusText = error.localizedDescription
                }
            }
        }
    }

    private static func summaryText(
        configuration: AppleConnectionConfiguration,
        deviceID: String?,
        status: String?
    ) -> String {
        let connection = configuration.connectionInput
        if let status {
            if let deviceID = deviceID?.nilIfBlank {
                return "\(status). Connection: \(connection). Device: \(deviceID)"
            }
            return "\(status). Connection: \(connection)"
        }

        if let deviceID = deviceID?.nilIfBlank {
            return "Connection: \(connection). Device: \(deviceID)"
        }

        return "Connection: \(connection)"
    }
}
