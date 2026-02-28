package io.ironmesh.android.data

import java.io.InputStream
import java.io.OutputStream

object RustClientBridge {
    private val libraryLoaded: Boolean = runCatching {
        System.loadLibrary("android_app")
        true
    }.getOrElse { false }

    @JvmStatic
    external fun putObject(baseUrl: String, key: String, payload: ByteArray): Int

    @JvmStatic
    external fun getObject(
        baseUrl: String,
        key: String,
        snapshot: String?,
        version: String?,
    ): ByteArray

    @JvmStatic
    external fun streamPutObject(
        baseUrl: String,
        key: String,
        input: InputStream,
    ): Int

    @JvmStatic
    external fun streamObjectTo(
        baseUrl: String,
        key: String,
        output: OutputStream,
        snapshot: String?,
        version: String?,
    )

    fun isAvailable(): Boolean = libraryLoaded
}
