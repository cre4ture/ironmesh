package io.ironmesh.android.data

data class DeviceIdentitySecret(
    val clusterId: String,
    val deviceId: String,
    val label: String?,
    val publicKeyPem: String,
    val privateKeyPem: String,
    val credentialPem: String,
    val rendezvousClientIdentityPem: String?,
) {
    fun applyingTo(state: DeviceAuthState): DeviceAuthState =
        state.copy(
            clusterId = clusterId,
            deviceId = deviceId,
            label = label,
            publicKeyPem = publicKeyPem,
            privateKeyPem = privateKeyPem,
            credentialPem = credentialPem,
            rendezvousClientIdentityPem = rendezvousClientIdentityPem,
        )

    companion object {
        fun fromState(state: DeviceAuthState): DeviceIdentitySecret? {
            if (!state.hasSensitiveIdentityMaterial()) {
                return null
            }

            return DeviceIdentitySecret(
                clusterId = state.clusterId.requiredIdentityValue("cluster ID"),
                deviceId = state.deviceId.requiredIdentityValue("device ID"),
                label = state.label?.takeIf { it.isNotBlank() },
                publicKeyPem = state.publicKeyPem.requiredIdentityValue("public key"),
                privateKeyPem = state.privateKeyPem.requiredIdentityValue("private key"),
                credentialPem = state.credentialPem.requiredIdentityValue("issued credential"),
                rendezvousClientIdentityPem =
                    state.rendezvousClientIdentityPem?.takeIf { it.isNotBlank() },
            )
        }

        private fun String?.requiredIdentityValue(name: String): String =
            this?.takeIf { it.isNotBlank() }
                ?: throw DeviceIdentityStorageException(
                    "The device identity is incomplete: it has no $name. Clear local enrollment and enroll this device again.",
                )
    }
}

interface DeviceIdentitySecretStore {
    fun load(): DeviceIdentitySecret?

    fun save(secret: DeviceIdentitySecret)

    fun clear()
}

open class DeviceIdentityStorageException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

class DeviceIdentityRecoveryRequiredException(
    cause: Throwable? = null,
) : DeviceIdentityStorageException(
    "The protected device identity is unavailable. Clear local enrollment and enroll this device again.",
    cause,
)

internal fun DeviceAuthState.hasSensitiveIdentityMaterial(): Boolean =
    !privateKeyPem.isNullOrBlank() ||
        !credentialPem.isNullOrBlank() ||
        !rendezvousClientIdentityPem.isNullOrBlank()

internal fun DeviceAuthState.hasIdentityMetadata(): Boolean =
    clusterId.isNotBlank() ||
        deviceId.isNotBlank() ||
        !publicKeyPem.isNullOrBlank()

internal fun DeviceAuthState.withoutSensitiveIdentityMaterial(): DeviceAuthState =
    copy(
        privateKeyPem = null,
        credentialPem = null,
        rendezvousClientIdentityPem = null,
    )
