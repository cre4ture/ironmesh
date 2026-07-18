import XCTest
@testable import AppleCore

final class AppleConnectionSettingsStoreTests: XCTestCase {
    func testSaveAndLoadKeepClientIdentityOutOfPreferences() throws {
        let testDefaults = try IsolatedDefaults(label: "RoundTrip")
        defer { testDefaults.clear() }
        let secretStore = InMemorySecretStore()
        let store = AppleConnectionSettingsStore(
            defaults: testDefaults.defaults,
            secretStore: secretStore
        )
        let identity = #"{"device_id":"device-1"}"#
        let state = AppleStoredConnectionState(
            connectionInput: #"{"version":1}"#,
            serverCAPem: "demo-ca",
            clientIdentityJSON: identity,
            deviceID: "device-1",
            deviceLabel: "Phone",
            bootstrapInputDraft: #"{"claim":true}"#
        )

        try store.save(state)

        XCTAssertEqual(secretStore.secret, identity)
        try assertPreferencesDoNotContainClientIdentity(
            defaults: testDefaults.defaults,
            secret: identity
        )
        XCTAssertEqual(try store.load(), state)
    }

    func testConnectionDraftEncodingNeverPersistsClientIdentity() throws {
        let identity = #"{"private_key_pem":"sensitive"}"#
        let draft = IronmeshConnectionDraft(
            directConnectionInput: "storage.example.test:443",
            clientIdentityJSON: identity
        )

        let data = try JSONEncoder().encode(draft)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )

        XCTAssertNil(object["clientIdentityJSON"])
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("private_key_pem"))
        let decodedDraft = try JSONDecoder().decode(
            IronmeshConnectionDraft.self,
            from: data
        )
        XCTAssertEqual(decodedDraft.clientIdentityJSON, "")
    }

    func testLoadMigratesLegacyIdentityFromBothPreferencesStores() throws {
        let sharedDefaults = try IsolatedDefaults(label: "SharedMigration")
        let draftDefaults = try IsolatedDefaults(label: "DraftMigration")
        defer {
            sharedDefaults.clear()
            draftDefaults.clear()
        }
        let appliedIdentity = #"{"private_key_pem":"applied-secret"}"#
        let draftIdentity = #"{"private_key_pem":"unapplied-draft-secret"}"#
        let legacyState = AppleStoredConnectionState(
            connectionInput: "storage.example.test:443",
            clientIdentityJSON: appliedIdentity,
            deviceID: "device-1"
        )
        sharedDefaults.defaults.set(
            try JSONEncoder().encode(legacyState),
            forKey: AppleConnectionSettingsStore.defaultStateKey
        )
        draftDefaults.defaults.set(
            try legacyDraftData(identity: draftIdentity),
            forKey: AppleConnectionSettingsStore.defaultLegacyDraftStateKey
        )
        let secretStore = InMemorySecretStore()
        let store = AppleConnectionSettingsStore(
            defaults: sharedDefaults.defaults,
            secretStore: secretStore
        )

        let loaded = try store.load(legacyDraftDefaults: draftDefaults.defaults)

        XCTAssertEqual(loaded?.clientIdentityJSON, appliedIdentity)
        XCTAssertEqual(loaded?.deviceID, "device-1")
        XCTAssertEqual(secretStore.secret, appliedIdentity)
        XCTAssertEqual(secretStore.saveCount, 1)
        try assertPreferencesDoNotContainClientIdentity(
            defaults: sharedDefaults.defaults,
            secret: appliedIdentity
        )
        try assertPreferencesDoNotContainClientIdentity(
            defaults: draftDefaults.defaults,
            stateKey: AppleConnectionSettingsStore.defaultLegacyDraftStateKey,
            secret: draftIdentity
        )
    }

    func testLegacyIdentityRemainsWhenKeychainMigrationFails() throws {
        let sharedDefaults = try IsolatedDefaults(label: "SharedMigrationFailure")
        let draftDefaults = try IsolatedDefaults(label: "DraftMigrationFailure")
        defer {
            sharedDefaults.clear()
            draftDefaults.clear()
        }
        let identity = #"{"private_key_pem":"legacy-secret"}"#
        sharedDefaults.defaults.set(
            try JSONEncoder().encode(
                AppleStoredConnectionState(clientIdentityJSON: identity)
            ),
            forKey: AppleConnectionSettingsStore.defaultStateKey
        )
        draftDefaults.defaults.set(
            try legacyDraftData(identity: identity),
            forKey: AppleConnectionSettingsStore.defaultLegacyDraftStateKey
        )
        let secretStore = InMemorySecretStore(saveError: .saveFailed)
        let store = AppleConnectionSettingsStore(
            defaults: sharedDefaults.defaults,
            secretStore: secretStore
        )

        XCTAssertThrowsError(
            try store.load(legacyDraftDefaults: draftDefaults.defaults)
        ) { error in
            XCTAssertEqual(error as? InMemorySecretStore.TestError, .saveFailed)
        }
        try assertPreferencesContainClientIdentity(
            defaults: sharedDefaults.defaults,
            identity: identity
        )
        try assertPreferencesContainClientIdentity(
            defaults: draftDefaults.defaults,
            stateKey: AppleConnectionSettingsStore.defaultLegacyDraftStateKey,
            identity: identity
        )
    }

    func testSaveFailureDoesNotPersistSanitizedState() throws {
        let testDefaults = try IsolatedDefaults(label: "SaveFailure")
        defer { testDefaults.clear() }
        let store = AppleConnectionSettingsStore(
            defaults: testDefaults.defaults,
            secretStore: InMemorySecretStore(saveError: .saveFailed)
        )

        XCTAssertThrowsError(
            try store.save(AppleStoredConnectionState(clientIdentityJSON: "secret"))
        ) { error in
            XCTAssertEqual(error as? InMemorySecretStore.TestError, .saveFailed)
        }
        let storedData = testDefaults.defaults.data(
            forKey: AppleConnectionSettingsStore.defaultStateKey
        )
        XCTAssertNil(storedData)
    }

    func testClearDeletesSecretAndPreferences() throws {
        let testDefaults = try IsolatedDefaults(label: "Clear")
        defer { testDefaults.clear() }
        let secretStore = InMemorySecretStore()
        let store = AppleConnectionSettingsStore(
            defaults: testDefaults.defaults,
            secretStore: secretStore
        )
        try store.save(
            AppleStoredConnectionState(
                connectionInput: "storage.example.test:443",
                clientIdentityJSON: "secret"
            )
        )

        try store.clear()

        XCTAssertNil(secretStore.secret)
        XCTAssertNil(try store.load())
    }

    func testClearFailureLeavesPreferencesUntouched() throws {
        let testDefaults = try IsolatedDefaults(label: "ClearFailure")
        defer { testDefaults.clear() }
        let secretStore = InMemorySecretStore()
        let store = AppleConnectionSettingsStore(
            defaults: testDefaults.defaults,
            secretStore: secretStore
        )
        try store.save(
            AppleStoredConnectionState(
                connectionInput: "storage.example.test:443",
                clientIdentityJSON: "secret"
            )
        )
        secretStore.clearError = .clearFailed

        XCTAssertThrowsError(try store.clear()) { error in
            XCTAssertEqual(error as? InMemorySecretStore.TestError, .clearFailed)
        }
        XCTAssertEqual(secretStore.secret, "secret")
        let storedData = testDefaults.defaults.data(
            forKey: AppleConnectionSettingsStore.defaultStateKey
        )
        XCTAssertNotNil(storedData)
    }

    func testLoadFailureLeavesLegacyPreferencesUntouched() throws {
        let testDefaults = try IsolatedDefaults(label: "LoadFailure")
        defer { testDefaults.clear() }
        let identity = #"{"private_key_pem":"legacy-secret"}"#
        testDefaults.defaults.set(
            try JSONEncoder().encode(
                AppleStoredConnectionState(clientIdentityJSON: identity)
            ),
            forKey: AppleConnectionSettingsStore.defaultStateKey
        )
        let store = AppleConnectionSettingsStore(
            defaults: testDefaults.defaults,
            secretStore: InMemorySecretStore(loadError: .loadFailed)
        )

        XCTAssertThrowsError(try store.load()) { error in
            XCTAssertEqual(error as? InMemorySecretStore.TestError, .loadFailed)
        }
        try assertPreferencesContainClientIdentity(
            defaults: testDefaults.defaults,
            identity: identity
        )
    }

    private func legacyDraftData(identity: String) throws -> Data {
        try JSONSerialization.data(
            withJSONObject: [
                "clientIdentityJSON": identity,
                "directConnectionInput": "storage.example.test:443",
            ],
            options: [.sortedKeys]
        )
    }

    private func assertPreferencesDoNotContainClientIdentity(
        defaults: UserDefaults,
        stateKey: String = AppleConnectionSettingsStore.defaultStateKey,
        secret: String
    ) throws {
        let data = try XCTUnwrap(defaults.data(forKey: stateKey))
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        XCTAssertNil(object["clientIdentityJSON"])
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("private_key_pem"))
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains(secret))
    }

    private func assertPreferencesContainClientIdentity(
        defaults: UserDefaults,
        stateKey: String = AppleConnectionSettingsStore.defaultStateKey,
        identity: String
    ) throws {
        let data = try XCTUnwrap(defaults.data(forKey: stateKey))
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        XCTAssertEqual(object["clientIdentityJSON"] as? String, identity)
    }
}

private struct IsolatedDefaults {
    let defaults: UserDefaults
    let suiteName: String

    init(label: String) throws {
        suiteName = "AppleConnectionSettingsStoreTests.\(label).\(UUID().uuidString)"
        defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        clear()
    }

    func clear() {
        defaults.removePersistentDomain(forName: suiteName)
    }
}

private final class InMemorySecretStore: AppleSecretStore, @unchecked Sendable {
    enum TestError: Error, Equatable {
        case loadFailed
        case saveFailed
        case clearFailed
    }

    var secret: String?
    var loadError: TestError?
    var saveError: TestError?
    var clearError: TestError?
    private(set) var saveCount = 0

    init(
        secret: String? = nil,
        loadError: TestError? = nil,
        saveError: TestError? = nil,
        clearError: TestError? = nil
    ) {
        self.secret = secret
        self.loadError = loadError
        self.saveError = saveError
        self.clearError = clearError
    }

    func load() throws -> String? {
        if let loadError {
            throw loadError
        }
        return secret
    }

    func save(_ secret: String) throws {
        if let saveError {
            throw saveError
        }
        self.secret = secret
        saveCount += 1
    }

    func clear() throws {
        if let clearError {
            throw clearError
        }
        secret = nil
    }
}
