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
    external fun enrollWithBootstrap(
        bootstrapJson: String,
        deviceId: String?,
        label: String?,
    ): String

    @JvmStatic
    external fun putObject(
        baseUrl: String,
        key: String,
        payload: ByteArray,
        serverCaPem: String?,
        authToken: String?,
    ): Int

    @JvmStatic
    external fun getObject(
        baseUrl: String,
        key: String,
        snapshot: String?,
        version: String?,
        serverCaPem: String?,
        authToken: String?,
    ): ByteArray

    @JvmStatic
    external fun storeIndex(
        baseUrl: String,
        prefix: String?,
        depth: Int,
        snapshot: String?,
        serverCaPem: String?,
        authToken: String?,
    ): String

    @JvmStatic
    external fun streamPutObject(
        baseUrl: String,
        key: String,
        input: InputStream,
        serverCaPem: String?,
        authToken: String?,
    ): Int

    @JvmStatic
    external fun deleteObject(
        baseUrl: String,
        key: String,
        serverCaPem: String?,
        authToken: String?,
    ): Int

    @JvmStatic
    external fun streamObjectTo(
        baseUrl: String,
        key: String,
        output: OutputStream,
        snapshot: String?,
        version: String?,
        serverCaPem: String?,
        authToken: String?,
    )

    @JvmStatic
    external fun streamRelativeUrlTo(
        baseUrl: String,
        relativeUrl: String,
        output: OutputStream,
        serverCaPem: String?,
        authToken: String?,
    )

    @JvmStatic
    external fun startWebUi(baseUrl: String): String

    fun isAvailable(): Boolean = libraryLoaded
}
