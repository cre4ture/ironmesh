package io.ironmesh.android.data

data class DeviceAuthState(
    val deviceId: String = "",
    val deviceToken: String = "",
    val label: String? = null,
) {
    fun hasToken(): Boolean = deviceToken.isNotBlank()
}
