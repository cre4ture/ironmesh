package io.ironmesh.android.data

import java.io.InputStream
import java.io.OutputStream

object RustClientBridge {
    private val libraryLoaded: Boolean = runCatching {
        System.loadLibrary("android_app")
        true
    }.getOrElse { false }

    @JvmStatic
    external fun enrollDevice(
        baseUrl: String,
        pairingToken: String,
        deviceId: String?,
        label: String?,
    ): String

    @JvmStatic
    external fun putObject(baseUrl: String, key: String, payload: ByteArray, authToken: String?): Int

    @JvmStatic
    external fun getObject(
        baseUrl: String,
        key: String,
        snapshot: String?,
        version: String?,
        authToken: String?,
    ): ByteArray

    @JvmStatic
    external fun storeIndex(
        baseUrl: String,
        prefix: String?,
        depth: Int,
        snapshot: String?,
        authToken: String?,
    ): String

    @JvmStatic
    external fun streamPutObject(
        baseUrl: String,
        key: String,
        input: InputStream,
        authToken: String?,
    ): Int

    @JvmStatic
    external fun deleteObject(baseUrl: String, key: String, authToken: String?): Int

    @JvmStatic
    external fun streamObjectTo(
        baseUrl: String,
        key: String,
        output: OutputStream,
        snapshot: String?,
        version: String?,
        authToken: String?,
    )

    @JvmStatic
    external fun startWebUi(baseUrl: String): String

    fun isAvailable(): Boolean = libraryLoaded
}
