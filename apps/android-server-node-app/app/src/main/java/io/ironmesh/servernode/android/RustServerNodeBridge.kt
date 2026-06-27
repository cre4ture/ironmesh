package io.ironmesh.servernode.android

import android.content.Context
import java.io.File

object RustServerNodeBridge {
    const val DEFAULT_BIND_HOST = "0.0.0.0"
    const val DEFAULT_BIND_PORT = 38443
    private const val LOCAL_UI_HOST = "127.0.0.1"

    init {
        System.loadLibrary("android_server_node_app")
    }

    @JvmStatic
    external fun startNode(dataDirPath: String, bindHost: String, bindPort: Int)

    @JvmStatic
    external fun stopNode()

    @JvmStatic
    private external fun statusJson(): String

    fun ensureStarted(context: Context) {
        val dataDir = File(context.noBackupFilesDir, "ironmesh-server-node")
        dataDir.mkdirs()
        startNode(dataDir.absolutePath, DEFAULT_BIND_HOST, DEFAULT_BIND_PORT)
    }

    fun stop() {
        stopNode()
    }

    fun localUiUrl(port: Int = DEFAULT_BIND_PORT): String = "https://$LOCAL_UI_HOST:$port"

    fun status(): ServerNodeStatus = ServerNodeStatus.fromJson(statusJson())
}
