import AppleCore
@preconcurrency import FileProvider
import Foundation
import UniformTypeIdentifiers

final class IronmeshFileProviderEnumerator: NSObject, NSFileProviderEnumerator, @unchecked Sendable {
    private let containerIdentifier: NSFileProviderItemIdentifier
    private let service: IronmeshFileProviderService

    init(containerIdentifier: NSFileProviderItemIdentifier, service: IronmeshFileProviderService) {
        self.containerIdentifier = containerIdentifier
        self.service = service
    }

    func invalidate() {
    }

    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        _ = page
        let observerBox = UncheckedBox(observer)
        DispatchQueue.global(qos: .userInitiated).async {
            let observer = observerBox.value
            do {
                if self.containerIdentifier == .workingSet {
                    observer.finishEnumerating(upTo: nil)
                    return
                }

                let containerItem = try self.service.item(for: self.containerIdentifier)
                let path = containerItem.identifier.kind == .root ? "" : normalizedPath(containerItem.path)
                let items = try self.service.list(path: path)
                let fileProviderItems = items.map {
                    IronmeshFileProviderItem(
                        bridgeItem: $0,
                        domainDisplayName: self.service.configuration.domainDisplayName
                    )
                }
                observer.didEnumerate(fileProviderItems)
                observer.finishEnumerating(upTo: nil)
            } catch {
                observer.finishEnumeratingWithError(asNSError(error))
            }
        }
    }

    func enumerateChanges(for observer: NSFileProviderChangeObserver, from syncAnchor: NSFileProviderSyncAnchor) {
        let observerBox = UncheckedBox(observer)
        DispatchQueue.global(qos: .utility).async {
            let observer = observerBox.value
            do {
                let anchorGeneration = try IronmeshSyncAnchorCodec.generation(from: syncAnchor)
                guard self.containerIdentifier == .workingSet else {
                    let generation = try self.service.currentChangeGeneration()
                    observer.finishEnumeratingChanges(
                        upTo: IronmeshSyncAnchorCodec.anchor(for: generation),
                        moreComing: false
                    )
                    return
                }

                let changes = try self.service.reconcileRemoteChanges(after: anchorGeneration)
                let updatedItems = changes.batch.updatedIdentifiers.compactMap {
                    changes.itemsByIdentifier[$0]
                }.map {
                    IronmeshFileProviderItem(
                        bridgeItem: $0,
                        domainDisplayName: self.service.configuration.domainDisplayName
                    )
                }
                if !updatedItems.isEmpty {
                    observer.didUpdate(updatedItems)
                }
                let deletedIdentifiers = changes.batch.deletedIdentifiers.map {
                    NSFileProviderItemIdentifier(rawValue: $0)
                }
                if !deletedIdentifiers.isEmpty {
                    observer.didDeleteItems(withIdentifiers: deletedIdentifiers)
                }
                observer.finishEnumeratingChanges(
                    upTo: IronmeshSyncAnchorCodec.anchor(for: changes.batch.generation),
                    moreComing: false
                )
            } catch AppleRemoteChangeJournalError.expiredAnchor {
                observer.finishEnumeratingWithError(fileProviderError(.syncAnchorExpired))
            } catch {
                observer.finishEnumeratingWithError(asNSError(error))
            }
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        let completion = UncheckedBox(completionHandler)
        DispatchQueue.global(qos: .utility).async {
            let generation = (try? self.service.currentChangeGeneration()) ?? 0
            completion.value(IronmeshSyncAnchorCodec.anchor(for: generation))
        }
    }
}
