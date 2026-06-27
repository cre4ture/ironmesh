package io.ironmesh.servernode.android

import org.json.JSONObject

data class ServerNodeStatus(
    val state: String = "stopped",
    val message: String = "Server node is stopped",
    val localUrl: String = "",
    val bindAddr: String = "",
    val dataDir: String = "",
    val mode: String? = null,
    val healthy: Boolean = false,
    val lastError: String? = null,
) {
    companion object {
        fun fromJson(raw: String): ServerNodeStatus {
            val obj = JSONObject(raw)
            return ServerNodeStatus(
                state = obj.optString("state", "stopped"),
                message = obj.optString("message", "Server node is stopped"),
                localUrl = obj.optString("localUrl", ""),
                bindAddr = obj.optString("bindAddr", ""),
                dataDir = obj.optString("dataDir", ""),
                mode = obj.optString("mode").takeIf { it.isNotBlank() },
                healthy = obj.optBoolean("healthy", false),
                lastError = obj.optString("lastError").takeIf { it.isNotBlank() },
            )
        }
    }
}
