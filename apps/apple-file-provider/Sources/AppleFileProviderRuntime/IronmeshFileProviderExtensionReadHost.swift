import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

extension IronmeshFileProviderExtensionHost {
    public func item(
        for identifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, (any Error)?) -> Void
    ) -> Progress {
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let item = try self.service.item(for: identifier)
                progress.completedUnitCount = 1
                completion.value(
                    IronmeshFileProviderItem(
                        bridgeItem: item,
                        domainDisplayName: self.service.configuration.domainDisplayName
                    ),
                    nil
                )
            } catch {
                completion.value(nil, asNSError(error))
            }
        }
        return progress
    }

    public func fetchContents(
        for itemIdentifier: NSFileProviderItemIdentifier,
        version requestedVersion: NSFileProviderItemVersion?,
        request: NSFileProviderRequest,
        completionHandler: @escaping (URL?, NSFileProviderItem?, (any Error)?) -> Void
    ) -> Progress {
        _ = requestedVersion
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let (fileURL, item) = try self.service.fetchContents(for: itemIdentifier)
                progress.completedUnitCount = 1
                completion.value(
                    fileURL,
                    IronmeshFileProviderItem(
                        bridgeItem: item,
                        domainDisplayName: self.service.configuration.domainDisplayName
                    ),
                    nil
                )
            } catch {
                completion.value(nil, nil, asNSError(error))
            }
        }
        return progress
    }

    public func enumerator(
        for containerItemIdentifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest
    ) throws -> any NSFileProviderEnumerator {
        _ = request
        return IronmeshFileProviderEnumerator(containerIdentifier: containerItemIdentifier, service: service)
    }
}
