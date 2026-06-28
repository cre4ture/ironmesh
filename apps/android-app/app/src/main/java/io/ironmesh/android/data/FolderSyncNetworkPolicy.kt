package io.ironmesh.android.data

data class FolderSyncNetworkPolicy(
    val allowWifi: Boolean = true,
    val allowCellular: Boolean = true,
    val allowOtherConnections: Boolean = true,
    val allowRoaming: Boolean = false,
    val allowedWifiSsids: List<String> = emptyList(),
) {
    fun normalized(): FolderSyncNetworkPolicy {
        return copy(
            allowedWifiSsids = allowedWifiSsids
                .map(::normalizeWifiSsid)
                .filter { it.isNotBlank() }
                .distinct(),
        )
    }

    fun hasAnyAllowedTransport(): Boolean {
        return allowWifi || allowCellular || allowOtherConnections
    }
}

fun normalizeWifiSsid(value: String): String {
    return value.trim().removeSurrounding("\"")
}

fun parseAllowedWifiSsidsInput(value: String): List<String> {
    return value
        .split(',', ';', '\n')
        .map(::normalizeWifiSsid)
        .filter { it.isNotBlank() }
        .distinct()
}

fun formatAllowedWifiSsidsInput(policy: FolderSyncNetworkPolicy): String {
    return policy.allowedWifiSsids.joinToString(", ")
}
