package io.ironmesh.servernode.android

import java.net.Inet4Address
import java.net.NetworkInterface

fun detectCandidateOrigins(port: Int): List<String> {
    return buildSet {
        val interfaces = runCatching { NetworkInterface.getNetworkInterfaces() }.getOrNull()
            ?: return@buildSet
        while (interfaces.hasMoreElements()) {
            val iface = interfaces.nextElement()
            val isUsable = runCatching { iface.isUp && !iface.isLoopback && !iface.isVirtual }
                .getOrDefault(false)
            if (!isUsable) {
                continue
            }
            val addresses = iface.inetAddresses
            while (addresses.hasMoreElements()) {
                val address = addresses.nextElement()
                if (address is Inet4Address && !address.isLoopbackAddress) {
                    add("https://${address.hostAddress}:$port")
                }
            }
        }
    }
        .sorted()
}
