package io.ironmesh.android.data

import com.squareup.moshi.JsonAdapter
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory

interface DeviceAuthPreferencesStorage {
    fun read(): String?

    fun write(value: String)

    fun clear()
}

class DeviceAuthStatePersistence(
    private val preferences: DeviceAuthPreferencesStorage,
    private val secretStore: DeviceIdentitySecretStore,
    private val codec: DeviceAuthStateCodec = DeviceAuthStateCodec(),
) {
    @Synchronized
    fun load(): DeviceAuthState {
        val persistedState = preferences.read()?.let(codec::decode) ?: DeviceAuthState()
        val protectedSecret = secretStore.load()
        val hasLegacySecret = persistedState.hasSensitiveIdentityMaterial()
        val legacySecret = if (protectedSecret == null && hasLegacySecret) {
            DeviceIdentitySecret.fromState(persistedState)
        } else {
            null
        }
        val effectiveSecret = protectedSecret ?: legacySecret

        if (hasLegacySecret) {
            secretStore.save(requireNotNull(effectiveSecret))
            preferences.write(codec.encode(persistedState.withoutSensitiveIdentityMaterial()))
        }

        if (effectiveSecret == null && persistedState.hasIdentityMetadata()) {
            throw DeviceIdentityRecoveryRequiredException()
        }

        val sanitizedState = persistedState.withoutSensitiveIdentityMaterial()
        return effectiveSecret?.applyingTo(sanitizedState) ?: sanitizedState
    }

    @Synchronized
    fun save(state: DeviceAuthState) {
        val secret = DeviceIdentitySecret.fromState(state)
        if (secret == null && state.hasIdentityMetadata()) {
            throw DeviceIdentityStorageException(
                "The device identity is incomplete. Enroll this device again before saving it.",
            )
        }

        val protectedSecret = runCatching { secretStore.load() }.getOrNull()
        if (secret == null) {
            secretStore.clear()
        } else {
            secretStore.save(secret)
        }
        try {
            preferences.write(codec.encode(state.withoutSensitiveIdentityMaterial()))
        } catch (error: Exception) {
            restoreProtectedSecret(protectedSecret, error)
            throw error
        }
    }

    @Synchronized
    fun clear() {
        // Clearing is the recovery path for a corrupt envelope or a lost Keystore key.
        val protectedSecret = runCatching { secretStore.load() }.getOrNull()
        secretStore.clear()
        try {
            preferences.clear()
        } catch (error: Exception) {
            restoreProtectedSecret(protectedSecret, error)
            throw error
        }
    }

    private fun restoreProtectedSecret(
        protectedSecret: DeviceIdentitySecret?,
        originalError: Exception,
    ) {
        try {
            if (protectedSecret == null) {
                secretStore.clear()
            } else {
                secretStore.save(protectedSecret)
            }
        } catch (restoreError: Exception) {
            originalError.addSuppressed(restoreError)
        }
    }
}

class DeviceAuthStateCodec(
    private val adapter: JsonAdapter<DeviceAuthState> = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()
        .adapter(DeviceAuthState::class.java),
) {
    fun encode(state: DeviceAuthState): String = adapter.toJson(state)

    fun decode(raw: String): DeviceAuthState =
        try {
            adapter.fromJson(raw)
                ?: throw DeviceIdentityStorageException(
                    "Stored device authentication settings are empty. Clear local enrollment and enroll again.",
                )
        } catch (error: DeviceIdentityStorageException) {
            throw error
        } catch (error: Exception) {
            throw DeviceIdentityStorageException(
                "Stored device authentication settings are damaged. Clear local enrollment and enroll again.",
                error,
            )
        }
}
