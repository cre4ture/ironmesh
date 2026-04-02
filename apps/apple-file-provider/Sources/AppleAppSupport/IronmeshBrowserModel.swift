import AppleCore
import FileProvider
import Foundation

@MainActor
final class IronmeshBrowserModel: ObservableObject {
    @Published var items: [AppleBridgeItem] = []
    @Published var statusText: String

    let service: IronmeshFileProviderService

    init(service: IronmeshFileProviderService = IronmeshFileProviderService()) {
        self.service = service
        statusText = "Connection: \(service.configuration.connectionInput)"
    }

    func refresh() {
        do {
            items = try service.list(path: "")
            statusText = "Loaded \(items.count) root item(s) from \(service.configuration.connectionInput)"
        } catch {
            statusText = error.localizedDescription
        }
    }

    func registerDomain() {
        service.registerDomain { error in
            Task { @MainActor in
                if let error {
                    self.statusText = error.localizedDescription
                } else {
                    self.statusText = "Registered File Provider domain \(self.service.configuration.domainIdentifier)"
                }
            }
        }
    }
}
