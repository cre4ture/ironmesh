package io.ironmesh.android.work

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import io.ironmesh.android.data.FolderSyncConfig
import io.ironmesh.android.data.FolderSyncNetworkPolicy
import io.ironmesh.android.data.normalizeWifiSsid

enum class FolderSyncActiveTransport {
    WIFI,
    CELLULAR,
    OTHER,
}

data class FolderSyncNetworkSnapshot(
    val connected: Boolean,
    val transports: Set<FolderSyncActiveTransport> = emptySet(),
    val wifiSsid: String? = null,
    val wifiNameVisible: Boolean = false,
    val isRoaming: Boolean = false,
)

data class FolderSyncNetworkDecision(
    val allowed: Boolean,
    val reason: String,
)

data class FolderSyncProfileNetworkDecision(
    val profile: FolderSyncConfig,
    val decision: FolderSyncNetworkDecision,
)

object FolderSyncNetworkGate {
    fun currentSnapshot(context: Context): FolderSyncNetworkSnapshot {
        val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
            ?: return FolderSyncNetworkSnapshot(connected = false)
        val activeNetwork = connectivityManager.activeNetwork
            ?: return FolderSyncNetworkSnapshot(connected = false)
        val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
            ?: return FolderSyncNetworkSnapshot(connected = false)

        val transports = buildSet {
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                add(FolderSyncActiveTransport.WIFI)
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                add(FolderSyncActiveTransport.CELLULAR)
            }
            if (
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_USB) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_LOWPAN) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI_AWARE) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            ) {
                add(FolderSyncActiveTransport.OTHER)
            }
        }

        return FolderSyncNetworkSnapshot(
            connected = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            transports = transports,
            wifiSsid = currentWifiSsid(context, capabilities, transports),
            wifiNameVisible = isWifiNameVisible(context),
            isRoaming = transports.contains(FolderSyncActiveTransport.CELLULAR) &&
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING),
        )
    }

    fun evaluate(
        policy: FolderSyncNetworkPolicy,
        snapshot: FolderSyncNetworkSnapshot,
    ): FolderSyncNetworkDecision {
        val normalizedPolicy = policy.normalized()
        if (!normalizedPolicy.hasAnyAllowedTransport()) {
            return FolderSyncNetworkDecision(
                allowed = false,
                reason = "No network type is allowed for this profile",
            )
        }
        if (!snapshot.connected) {
            return FolderSyncNetworkDecision(
                allowed = false,
                reason = "No active internet connection",
            )
        }

        if (snapshot.transports.contains(FolderSyncActiveTransport.WIFI)) {
            if (normalizedPolicy.allowWifi) {
                val allowedSsids = normalizedPolicy.allowedWifiSsids
                if (allowedSsids.isEmpty()) {
                    return FolderSyncNetworkDecision(allowed = true, reason = "Wi-Fi allowed")
                }
                val currentSsid = snapshot.wifiSsid
                if (currentSsid == null) {
                    val reason = if (snapshot.wifiNameVisible) {
                        "Connected Wi-Fi name is unavailable"
                    } else {
                        "Wi-Fi name permission or device location is required"
                    }
                    return FolderSyncNetworkDecision(allowed = false, reason = reason)
                }
                if (allowedSsids.contains(normalizeWifiSsid(currentSsid))) {
                    return FolderSyncNetworkDecision(
                        allowed = true,
                        reason = "Wi-Fi '$currentSsid' allowed",
                    )
                }
                return FolderSyncNetworkDecision(
                    allowed = false,
                    reason = "Wi-Fi '$currentSsid' is not in the allowed list",
                )
            }
        }

        if (snapshot.transports.contains(FolderSyncActiveTransport.CELLULAR)) {
            if (!normalizedPolicy.allowCellular) {
                return FolderSyncNetworkDecision(
                    allowed = false,
                    reason = "Mobile data is disabled for this profile",
                )
            }
            if (snapshot.isRoaming && !normalizedPolicy.allowRoaming) {
                return FolderSyncNetworkDecision(
                    allowed = false,
                    reason = "Roaming is blocked for this profile",
                )
            }
            return FolderSyncNetworkDecision(
                allowed = true,
                reason = if (snapshot.isRoaming) {
                    "Roaming mobile data allowed"
                } else {
                    "Mobile data allowed"
                },
            )
        }

        if (snapshot.transports.contains(FolderSyncActiveTransport.OTHER)) {
            if (normalizedPolicy.allowOtherConnections) {
                return FolderSyncNetworkDecision(
                    allowed = true,
                    reason = "Other network connection allowed",
                )
            }
            return FolderSyncNetworkDecision(
                allowed = false,
                reason = "Only Wi-Fi or mobile data is allowed",
            )
        }

        return FolderSyncNetworkDecision(
            allowed = false,
            reason = "Connected network type is not supported by this profile",
        )
    }

    fun evaluateProfiles(
        context: Context,
        profiles: List<FolderSyncConfig>,
    ): List<FolderSyncProfileNetworkDecision> {
        val snapshot = currentSnapshot(context)
        return profiles.map { profile ->
            FolderSyncProfileNetworkDecision(
                profile = profile,
                decision = evaluate(profile.networkPolicy, snapshot),
            )
        }
    }

    private fun currentWifiSsid(
        context: Context,
        capabilities: NetworkCapabilities,
        transports: Set<FolderSyncActiveTransport>,
    ): String? {
        if (!transports.contains(FolderSyncActiveTransport.WIFI)) {
            return null
        }

        val fromTransportInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            (capabilities.transportInfo as? WifiInfo)?.ssid
        } else {
            null
        }
        normalizeWifiName(fromTransportInfo)?.let { return it }

        @Suppress("DEPRECATION")
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        @Suppress("DEPRECATION")
        return normalizeWifiName(wifiManager?.connectionInfo?.ssid)
    }

    private fun isWifiNameVisible(context: Context): Boolean {
        val hasWifiPermission = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_WIFI_STATE,
        ) == PackageManager.PERMISSION_GRANTED
        if (!hasWifiPermission) {
            return false
        }

        val hasLocationPermission = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION,
        ) == PackageManager.PERMISSION_GRANTED
        if (!hasLocationPermission || !isLocationEnabled(context)) {
            return false
        }

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.NEARBY_WIFI_DEVICES,
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    private fun isLocationEnabled(context: Context): Boolean {
        val locationManager = context.getSystemService(LocationManager::class.java) ?: return false
        return runCatching {
            locationManager.isLocationEnabled
        }.getOrDefault(false)
    }

    private fun normalizeWifiName(rawValue: String?): String? {
        val normalized = rawValue
            ?.takeUnless { it == WifiManager.UNKNOWN_SSID }
            ?.let(::normalizeWifiSsid)
            ?.takeIf { it.isNotBlank() }
        return normalized
    }
}
