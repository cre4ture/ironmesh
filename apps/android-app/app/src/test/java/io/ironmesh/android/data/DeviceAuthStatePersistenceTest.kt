package io.ironmesh.android.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceAuthStatePersistenceTest {
    private val codec = DeviceAuthStateCodec()

    @Test
    fun saveAndLoadRoundTripKeepsSecretsOutOfPreferences() {
        val events = mutableListOf<String>()
        val preferences = InMemoryDeviceAuthPreferences(events = events)
        val secretStore = InMemoryDeviceIdentitySecretStore(events = events)
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)
        val state = completeState()

        persistence.save(state)

        assertEquals(listOf("secret.load", "secret.save", "preferences.write"), events)
        assertPreferencesAreSanitized(preferences.raw.orEmpty())
        assertEquals(state, persistence.load())
    }

    @Test
    fun loadMigratesCompleteLegacyIdentityAfterProtectedWriteSucceeds() {
        val legacyState = completeState(privateKeyPem = "legacy-private")
        val preferences = InMemoryDeviceAuthPreferences(raw = codec.encode(legacyState))
        val secretStore = InMemoryDeviceIdentitySecretStore()
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        val loaded = persistence.load()

        assertEquals(legacyState, loaded)
        assertEquals("legacy-private", secretStore.secret?.privateKeyPem)
        assertEquals(1, secretStore.saveCount)
        assertPreferencesAreSanitized(preferences.raw.orEmpty())
    }

    @Test
    fun loadRejectsLegacyPrivateKeyWithoutCredentialBeforeMigration() {
        val legacyState = completeState().copy(credentialPem = null)
        val rawLegacyState = codec.encode(legacyState)
        val events = mutableListOf<String>()
        val preferences = InMemoryDeviceAuthPreferences(
            raw = rawLegacyState,
            events = events,
        )
        val secretStore = InMemoryDeviceIdentitySecretStore(events = events)
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        val error = assertThrows(DeviceIdentityStorageException::class.java) {
            persistence.load()
        }

        assertTrue(error.message.orEmpty().contains("issued credential"))
        assertTrue(error.message.orEmpty().contains("enroll this device again"))
        assertEquals(listOf("secret.load"), events)
        assertEquals(0, secretStore.saveCount)
        assertNull(secretStore.secret)
        assertEquals(rawLegacyState, preferences.raw)
        assertTrue(preferences.raw.orEmpty().contains("private-key-secret"))
    }

    @Test
    fun protectedIdentityWinsOverDifferingPartialLegacyFields() {
        val protectedState = completeState(
            deviceId = "applied-device",
            privateKeyPem = "applied-private",
        )
        val malformedLegacy = completeState(
            deviceId = "legacy-device",
            privateKeyPem = "legacy-private",
        ).copy(publicKeyPem = null)
        val preferences = InMemoryDeviceAuthPreferences(raw = codec.encode(malformedLegacy))
        val secretStore = InMemoryDeviceIdentitySecretStore(
            secret = requireNotNull(DeviceIdentitySecret.fromState(protectedState)),
        )
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        val loaded = persistence.load()

        assertEquals(protectedState, loaded)
        assertEquals("applied-device", loaded.deviceId)
        assertEquals("applied-private", loaded.privateKeyPem)
        assertEquals(1, secretStore.saveCount)
        assertPreferencesAreSanitized(preferences.raw.orEmpty())
    }

    @Test
    fun malformedLegacyJsonFailsExplicitlyWithoutChangingPreferences() {
        val malformed = "{not-json"
        val preferences = InMemoryDeviceAuthPreferences(raw = malformed)
        val secretStore = InMemoryDeviceIdentitySecretStore()
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        val error = assertThrows(DeviceIdentityStorageException::class.java) {
            persistence.load()
        }

        assertTrue(error.message.orEmpty().contains("damaged"))
        assertEquals(malformed, preferences.raw)
        assertEquals(0, secretStore.saveCount)
    }

    @Test
    fun failedLegacyMigrationLeavesCleartextUntouched() {
        val legacyState = completeState(privateKeyPem = "legacy-private")
        val preferences = InMemoryDeviceAuthPreferences(raw = codec.encode(legacyState))
        val secretStore = InMemoryDeviceIdentitySecretStore(saveError = TestFailure("save failed"))
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        assertThrows(TestFailure::class.java) {
            persistence.load()
        }

        assertTrue(preferences.raw.orEmpty().contains("legacy-private"))
        assertNull(secretStore.secret)
    }

    @Test
    fun failedSecretSaveDoesNotWriteSanitizedPreferences() {
        val events = mutableListOf<String>()
        val preferences = InMemoryDeviceAuthPreferences(events = events)
        val secretStore = InMemoryDeviceIdentitySecretStore(
            events = events,
            saveError = TestFailure("save failed"),
        )
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        assertThrows(TestFailure::class.java) {
            persistence.save(completeState())
        }

        assertEquals(listOf("secret.load", "secret.save"), events)
        assertNull(preferences.raw)
    }

    @Test
    fun saveRejectsPrivateKeyWithBlankCredentialBeforeWritingAnything() {
        val events = mutableListOf<String>()
        val preferences = InMemoryDeviceAuthPreferences(events = events)
        val secretStore = InMemoryDeviceIdentitySecretStore(events = events)
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        val error = assertThrows(DeviceIdentityStorageException::class.java) {
            persistence.save(completeState().copy(credentialPem = "   "))
        }

        assertTrue(error.message.orEmpty().contains("issued credential"))
        assertTrue(error.message.orEmpty().contains("enroll this device again"))
        assertTrue(events.isEmpty())
        assertEquals(0, secretStore.saveCount)
        assertNull(secretStore.secret)
        assertNull(preferences.raw)
    }

    @Test
    fun failedPreferencesWriteAfterNewSecretRestoresPreviousIdentity() {
        val events = mutableListOf<String>()
        val oldSecret = requireNotNull(DeviceIdentitySecret.fromState(completeState()))
        val preferences = InMemoryDeviceAuthPreferences(
            events = events,
            writeError = TestFailure("write failed"),
        )
        val secretStore = InMemoryDeviceIdentitySecretStore(
            secret = oldSecret,
            events = events,
        )
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        assertThrows(TestFailure::class.java) {
            persistence.save(
                completeState(
                    deviceId = "replacement-device",
                    privateKeyPem = "replacement-private",
                ),
            )
        }

        assertEquals(
            listOf("secret.load", "secret.save", "preferences.write", "secret.save"),
            events,
        )
        assertEquals(oldSecret, secretStore.secret)
        assertNull(preferences.raw)
    }

    @Test
    fun failedPreferencesWriteWhileRemovingIdentityRestoresProtectedSecret() {
        val events = mutableListOf<String>()
        val oldState = completeState()
        val originalSecret = requireNotNull(DeviceIdentitySecret.fromState(oldState))
        val preferences = InMemoryDeviceAuthPreferences(
            raw = codec.encode(oldState.withoutSensitiveIdentityMaterial()),
            events = events,
            writeError = TestFailure("write failed"),
        )
        val secretStore = InMemoryDeviceIdentitySecretStore(
            secret = originalSecret,
            events = events,
        )
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)
        val bootstrapOnlyState = DeviceAuthState(connectionBootstrapJson = "{\"version\":2}")

        assertThrows(TestFailure::class.java) {
            persistence.save(bootstrapOnlyState)
        }

        assertEquals(
            listOf("secret.load", "secret.clear", "preferences.write", "secret.save"),
            events,
        )
        assertEquals(originalSecret, secretStore.secret)
        assertTrue(preferences.raw.orEmpty().contains("cluster-1"))
    }

    @Test
    fun failedPreferencesClearRestoresProtectedSecretAfterClearFirstOrdering() {
        val events = mutableListOf<String>()
        val state = completeState()
        val preferences = InMemoryDeviceAuthPreferences(
            raw = codec.encode(state.withoutSensitiveIdentityMaterial()),
            events = events,
            clearError = TestFailure("clear failed"),
        )
        val originalSecret = requireNotNull(DeviceIdentitySecret.fromState(state))
        val secretStore = InMemoryDeviceIdentitySecretStore(
            secret = originalSecret,
            events = events,
        )
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        assertThrows(TestFailure::class.java) {
            persistence.clear()
        }

        assertEquals(
            listOf("secret.load", "secret.clear", "preferences.clear", "secret.save"),
            events,
        )
        assertEquals(originalSecret, secretStore.secret)
        assertTrue(preferences.raw.orEmpty().isNotBlank())
    }

    @Test
    fun corruptedCiphertextIsAnExplicitRecoverableError() {
        val raw = codec.encode(completeState().withoutSensitiveIdentityMaterial())
        val preferences = InMemoryDeviceAuthPreferences(raw = raw)
        val secretStore = InMemoryDeviceIdentitySecretStore(
            loadError = DeviceIdentityRecoveryRequiredException(TestFailure("bad tag")),
        )
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        val error = assertThrows(DeviceIdentityRecoveryRequiredException::class.java) {
            persistence.load()
        }

        assertTrue(error.message.orEmpty().contains("enroll this device again"))
        assertEquals(raw, preferences.raw)
    }

    @Test
    fun clearRemainsAvailableWhenProtectedIdentityCannotBeRead() {
        val events = mutableListOf<String>()
        val preferences = InMemoryDeviceAuthPreferences(
            raw = codec.encode(completeState().withoutSensitiveIdentityMaterial()),
            events = events,
        )
        val secretStore = InMemoryDeviceIdentitySecretStore(
            events = events,
            loadError = DeviceIdentityRecoveryRequiredException(TestFailure("key lost")),
        )
        val persistence = DeviceAuthStatePersistence(preferences, secretStore, codec)

        persistence.clear()

        assertEquals(listOf("secret.load", "secret.clear", "preferences.clear"), events)
        assertNull(preferences.raw)
        assertNull(secretStore.secret)
    }

    @Test
    fun missingKeystoreSecretForAppliedMetadataRequiresReEnrollment() {
        val raw = codec.encode(completeState().withoutSensitiveIdentityMaterial())
        val preferences = InMemoryDeviceAuthPreferences(raw = raw)
        val persistence = DeviceAuthStatePersistence(
            preferences,
            InMemoryDeviceIdentitySecretStore(),
            codec,
        )

        val error = assertThrows(DeviceIdentityRecoveryRequiredException::class.java) {
            persistence.load()
        }

        assertTrue(error.message.orEmpty().contains("enroll this device again"))
        assertEquals(raw, preferences.raw)
    }

    private fun assertPreferencesAreSanitized(raw: String) {
        assertFalse(raw.contains("privateKeyPem"))
        assertFalse(raw.contains("credentialPem"))
        assertFalse(raw.contains("rendezvousClientIdentityPem"))
        assertFalse(raw.contains("private_key"))
        assertFalse(raw.contains("issued-credential"))
        assertFalse(raw.contains("rendezvous-secret"))
    }

    private fun completeState(
        deviceId: String = "device-1",
        privateKeyPem: String = "private-key-secret",
    ): DeviceAuthState =
        DeviceAuthState(
            clusterId = "cluster-1",
            deviceId = deviceId,
            label = "Phone",
            connectionBootstrapJson = "{\"version\":1}",
            directServerBaseUrl = "https://storage.example.test/",
            serverCaPem = "demo-ca",
            publicKeyPem = "public-key",
            privateKeyPem = privateKeyPem,
            credentialPem = "issued-credential",
            rendezvousClientIdentityPem = "rendezvous-secret",
        )
}

private class InMemoryDeviceAuthPreferences(
    var raw: String? = null,
    private val events: MutableList<String> = mutableListOf(),
    private val writeError: Exception? = null,
    private val clearError: Exception? = null,
) : DeviceAuthPreferencesStorage {
    override fun read(): String? = raw

    override fun write(value: String) {
        events += "preferences.write"
        writeError?.let { throw it }
        raw = value
    }

    override fun clear() {
        events += "preferences.clear"
        clearError?.let { throw it }
        raw = null
    }
}

private class InMemoryDeviceIdentitySecretStore(
    var secret: DeviceIdentitySecret? = null,
    private val events: MutableList<String> = mutableListOf(),
    private val loadError: Exception? = null,
    private val saveError: Exception? = null,
    private val clearError: Exception? = null,
) : DeviceIdentitySecretStore {
    var saveCount = 0
        private set

    override fun load(): DeviceIdentitySecret? {
        events += "secret.load"
        loadError?.let { throw it }
        return secret
    }

    override fun save(secret: DeviceIdentitySecret) {
        events += "secret.save"
        saveError?.let { throw it }
        this.secret = secret
        saveCount += 1
    }

    override fun clear() {
        events += "secret.clear"
        clearError?.let { throw it }
        secret = null
    }
}

private class TestFailure(message: String) : Exception(message)
