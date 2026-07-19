import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

extension IronmeshFileProviderExtensionHost {
    public func createItem(
        basedOn itemTemplate: NSFileProviderItem,
        fields: NSFileProviderItemFields,
        contents url: URL?,
        options: NSFileProviderCreateItemOptions,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, (any Error)?) -> Void
    ) -> Progress {
        _ = fields
        _ = options
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let item = try self.service.createItem(
                    parentIdentifier: itemTemplate.parentItemIdentifier,
                    filename: itemTemplate.filename,
                    contentType: itemTemplate.contentType ?? .data,
                    contents: url
                )
                progress.completedUnitCount = 1
                completion.value(
                    self.providerItem(item),
                    [],
                    false,
                    nil
                )
            } catch {
                completion.value(nil, [], false, asNSError(error))
            }
        }
        return progress
    }

    public func modifyItem(
        _ item: NSFileProviderItem,
        baseVersion: NSFileProviderItemVersion,
        changedFields: NSFileProviderItemFields,
        contents url: URL?,
        options: NSFileProviderModifyItemOptions,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, (any Error)?) -> Void
    ) -> Progress {
        _ = options
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        let supportedFields: NSFileProviderItemFields = [
            .contents,
            .filename,
            .parentItemIdentifier
        ]
        let actionableFields = changedFields.intersection(supportedFields)
        let unsupportedFields = changedFields.subtracting(supportedFields)

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let updatedItem: AppleBridgeItem
                if actionableFields.isEmpty {
                    updatedItem = try self.service.item(for: item.itemIdentifier)
                } else {
                    updatedItem = try self.service.modifyItem(
                        identifier: item.itemIdentifier,
                        filename: item.filename,
                        parentIdentifier: item.parentItemIdentifier,
                        contentType: item.contentType ?? .data,
                        changedFields: actionableFields,
                        contents: url,
                        expectedRevision: String(
                            data: baseVersion.contentVersion,
                            encoding: .utf8
                        )
                    )
                }

                progress.completedUnitCount = 1
                completion.value(
                    self.providerItem(updatedItem),
                    unsupportedFields,
                    false,
                    nil
                )
            } catch {
                self.workingSetSignals.signalIfConflictCopyWasCreated(error)
                completion.value(nil, [], false, asNSError(error))
            }
        }
        return progress
    }

    public func deleteItem(
        identifier itemIdentifier: NSFileProviderItemIdentifier,
        baseVersion: NSFileProviderItemVersion,
        options: NSFileProviderDeleteItemOptions,
        request: NSFileProviderRequest,
        completionHandler: @escaping ((any Error)?) -> Void
    ) -> Progress {
        _ = request
        let progress = Progress(totalUnitCount: 1)
        let completion = UncheckedBox(completionHandler)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.service.deleteItem(
                    identifier: itemIdentifier,
                    options: options,
                    expectedRevision: String(
                        data: baseVersion.contentVersion,
                        encoding: .utf8
                    )
                )
                progress.completedUnitCount = 1
                completion.value(nil)
            } catch {
                completion.value(asNSError(error))
            }
        }
        return progress
    }

    func providerItem(_ bridgeItem: AppleBridgeItem) -> IronmeshFileProviderItem {
        IronmeshFileProviderItem(
            bridgeItem: bridgeItem,
            domainDisplayName: service.configuration.domainDisplayName
        )
    }
}
