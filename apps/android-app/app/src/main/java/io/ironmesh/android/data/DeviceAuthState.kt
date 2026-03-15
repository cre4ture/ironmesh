package io.ironmesh.android.data

import org.json.JSONObject

data class DeviceAuthState(
    val clusterId: String = "",
    val deviceId: String = "",
    val deviceToken: String = "",
    val label: String? = null,
    val serverBaseUrl: String = "",
    val serverCaPem: String? = null,
    val publicKeyPem: String? = null,
    val privateKeyPem: String? = null,
    val credentialPem: String? = null,
) {
    fun hasClientIdentity(): Boolean =
        clusterId.isNotBlank() &&
            deviceId.isNotBlank() &&
            !publicKeyPem.isNullOrBlank() &&
            !privateKeyPem.isNullOrBlank() &&
            !credentialPem.isNullOrBlank()

    fun hasToken(): Boolean = hasClientIdentity()

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
        }.toString()
    }
}
