package io.ironmesh.android.data

import org.json.JSONObject

data class DeviceAuthState(
    val clusterId: String = "",
    val deviceId: String = "",
    val label: String? = null,
    val connectionBootstrapJson: String = "",
    val serverBaseUrl: String = "",
    val serverCaPem: String? = null,
    val publicKeyPem: String? = null,
    val privateKeyPem: String? = null,
    val credentialPem: String? = null,
    val rendezvousClientIdentityPem: String? = null,
) {
    fun hasClientIdentity(): Boolean =
        clusterId.isNotBlank() &&
            deviceId.isNotBlank() &&
            !publicKeyPem.isNullOrBlank() &&
            !privateKeyPem.isNullOrBlank() &&
            !credentialPem.isNullOrBlank()

    fun hasToken(): Boolean = hasClientIdentity()

    fun preferredConnectionInput(fallbackBaseUrl: String? = null): String {
        val bootstrapJson = connectionBootstrapJson.trim()
        if (bootstrapJson.isNotEmpty()) {
            return bootstrapJson
        }

        val directBaseUrl = serverBaseUrl.trim()
        if (directBaseUrl.isNotEmpty()) {
            return directBaseUrl
        }

        return fallbackBaseUrl?.trim().orEmpty()
    }

    fun toClientIdentityJson(): String? {
        if (!hasClientIdentity()) {
            return null
        }

        return JSONObject().apply {
            put("cluster_id", clusterId)
            put("device_id", deviceId)
            if (!label.isNullOrBlank()) {
                put("label", label)
            }
            put("private_key_pem", privateKeyPem)
            put("public_key_pem", publicKeyPem)
            put("credential_pem", credentialPem)
            if (!rendezvousClientIdentityPem.isNullOrBlank()) {
                put("rendezvous_client_identity_pem", rendezvousClientIdentityPem)
            }
        }.toString()
    }
}
