import AppleCore
@preconcurrency import FileProvider
import Foundation
import Network

protocol IronmeshSyncEnvironmentProviding: Sendable {
    func snapshot() -> AppleSyncEnvironmentSnapshot
}

protocol IronmeshSyncEnvironmentObserving: IronmeshSyncEnvironmentProviding {
    func addChangeObserver(
        _ observer: @escaping @Sendable (
            AppleSyncEnvironmentSnapshot,
            AppleSyncEnvironmentSnapshot
        ) -> Void
    ) -> UUID
    func removeChangeObserver(_ token: UUID)
}

final class IronmeshLiveSyncEnvironment: IronmeshSyncEnvironmentObserving, @unchecked Sendable {
    static let shared = IronmeshLiveSyncEnvironment()

    private let monitor = NWPathMonitor()
    private let lock = NSLock()
    private let callbackQueue = DispatchQueue(label: "dev.ironmesh.apple.sync-environment-callbacks")
    private var latestSnapshot: AppleSyncEnvironmentSnapshot
    private var observers: [UUID: @Sendable (
        AppleSyncEnvironmentSnapshot,
        AppleSyncEnvironmentSnapshot
    ) -> Void] = [:]
    private var powerStateObserver: NSObjectProtocol?

    private init() {
        latestSnapshot = Self.makeSnapshot(
            path: monitor.currentPath,
            isLowPowerModeEnabled: ProcessInfo.processInfo.isLowPowerModeEnabled
        )
        monitor.pathUpdateHandler = { [weak self] path in
            self?.update(path: path)
        }
        powerStateObserver = NotificationCenter.default.addObserver(
            forName: Notification.Name.NSProcessInfoPowerStateDidChange,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.updateLowPowerMode()
        }
        monitor.start(queue: DispatchQueue(label: "dev.ironmesh.apple.sync-network-path"))
    }

    deinit {
        monitor.cancel()
        if let powerStateObserver {
            NotificationCenter.default.removeObserver(powerStateObserver)
        }
    }

    func snapshot() -> AppleSyncEnvironmentSnapshot {
        lock.lock()
        let snapshot = latestSnapshot
        lock.unlock()
        return snapshot
    }

    func addChangeObserver(
        _ observer: @escaping @Sendable (
            AppleSyncEnvironmentSnapshot,
            AppleSyncEnvironmentSnapshot
        ) -> Void
    ) -> UUID {
        let token = UUID()
        lock.lock()
        observers[token] = observer
        lock.unlock()
        return token
    }

    func removeChangeObserver(_ token: UUID) {
        lock.lock()
        observers.removeValue(forKey: token)
        lock.unlock()
    }

    private func update(path: NWPath) {
        mutateSnapshot { snapshot in
            snapshot = Self.makeSnapshot(
                path: path,
                isLowPowerModeEnabled: ProcessInfo.processInfo.isLowPowerModeEnabled
            )
        }
    }

    private func updateLowPowerMode() {
        mutateSnapshot { snapshot in
            snapshot.isLowPowerModeEnabled = ProcessInfo.processInfo.isLowPowerModeEnabled
        }
    }

    private func mutateSnapshot(
        _ mutation: (inout AppleSyncEnvironmentSnapshot) -> Void
    ) {
        lock.lock()
        let previous = latestSnapshot
        mutation(&latestSnapshot)
        let current = latestSnapshot
        guard previous != current else {
            lock.unlock()
            return
        }
        let callbacks = Array(observers.values)
        callbackQueue.async {
            callbacks.forEach { $0(previous, current) }
        }
        lock.unlock()
    }

    private static func makeSnapshot(
        path: NWPath,
        isLowPowerModeEnabled: Bool
    ) -> AppleSyncEnvironmentSnapshot {
        AppleSyncEnvironmentSnapshot(
            isConnected: path.status == .satisfied,
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained,
            isLowPowerModeEnabled: isLowPowerModeEnabled
        )
    }
}
