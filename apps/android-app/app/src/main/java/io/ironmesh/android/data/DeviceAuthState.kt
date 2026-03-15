package io.ironmesh.android.data

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
    fun hasToken(): Boolean = deviceToken.isNotBlank()
}
