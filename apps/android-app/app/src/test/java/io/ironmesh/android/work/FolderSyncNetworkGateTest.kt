package io.ironmesh.android.work

import io.ironmesh.android.data.FolderSyncNetworkPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FolderSyncNetworkGateTest {
    @Test
    fun evaluate_allowsWifiWhenWhitelistedSsidMatches() {
        val decision = FolderSyncNetworkGate.evaluate(
            policy = FolderSyncNetworkPolicy(
                allowWifi = true,
                allowCellular = false,
                allowOtherConnections = false,
                allowedWifiSsids = listOf("Home WiFi"),
            ),
            snapshot = FolderSyncNetworkSnapshot(
                connected = true,
                transports = setOf(FolderSyncActiveTransport.WIFI),
                wifiSsid = "Home WiFi",
                wifiNameVisible = true,
            ),
        )

        assertTrue(decision.allowed)
        assertEquals("Wi-Fi 'Home WiFi' allowed", decision.reason)
    }

    @Test
    fun evaluate_blocksWifiWhenSsidDoesNotMatchWhitelist() {
        val decision = FolderSyncNetworkGate.evaluate(
            policy = FolderSyncNetworkPolicy(
                allowWifi = true,
                allowCellular = false,
                allowOtherConnections = false,
                allowedWifiSsids = listOf("Home WiFi"),
            ),
            snapshot = FolderSyncNetworkSnapshot(
                connected = true,
                transports = setOf(FolderSyncActiveTransport.WIFI),
                wifiSsid = "Cafe WiFi",
                wifiNameVisible = true,
            ),
        )

        assertFalse(decision.allowed)
        assertEquals("Wi-Fi 'Cafe WiFi' is not in the allowed list", decision.reason)
    }

    @Test
    fun evaluate_blocksWifiWhenWhitelistRequiresUnavailableWifiName() {
        val decision = FolderSyncNetworkGate.evaluate(
            policy = FolderSyncNetworkPolicy(
                allowWifi = true,
                allowCellular = false,
                allowOtherConnections = false,
                allowedWifiSsids = listOf("Home WiFi"),
            ),
            snapshot = FolderSyncNetworkSnapshot(
                connected = true,
                transports = setOf(FolderSyncActiveTransport.WIFI),
                wifiSsid = null,
                wifiNameVisible = false,
            ),
        )

        assertFalse(decision.allowed)
        assertEquals("Wi-Fi name permission or device location is required", decision.reason)
    }

    @Test
    fun evaluate_blocksRoamingCellularWhenPolicyDisallowsIt() {
        val decision = FolderSyncNetworkGate.evaluate(
            policy = FolderSyncNetworkPolicy(
                allowWifi = false,
                allowCellular = true,
                allowOtherConnections = false,
                allowRoaming = false,
            ),
            snapshot = FolderSyncNetworkSnapshot(
                connected = true,
                transports = setOf(FolderSyncActiveTransport.CELLULAR),
                isRoaming = true,
            ),
        )

        assertFalse(decision.allowed)
        assertEquals("Roaming is blocked for this profile", decision.reason)
    }

    @Test
    fun evaluate_allowsOtherTransportWhenExplicitlyEnabled() {
        val decision = FolderSyncNetworkGate.evaluate(
            policy = FolderSyncNetworkPolicy(
                allowWifi = false,
                allowCellular = false,
                allowOtherConnections = true,
            ),
            snapshot = FolderSyncNetworkSnapshot(
                connected = true,
                transports = setOf(FolderSyncActiveTransport.OTHER),
            ),
        )

        assertTrue(decision.allowed)
        assertEquals("Other network connection allowed", decision.reason)
    }

    @Test
    fun evaluate_blocksWhenNoTransportIsAllowedByPolicy() {
        val decision = FolderSyncNetworkGate.evaluate(
            policy = FolderSyncNetworkPolicy(
                allowWifi = false,
                allowCellular = false,
                allowOtherConnections = false,
            ),
            snapshot = FolderSyncNetworkSnapshot(
                connected = true,
                transports = setOf(FolderSyncActiveTransport.WIFI),
                wifiSsid = "Home WiFi",
                wifiNameVisible = true,
            ),
        )

        assertFalse(decision.allowed)
        assertEquals("No network type is allowed for this profile", decision.reason)
    }
}
