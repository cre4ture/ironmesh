package io.ironmesh.android.data

object RustClientBridge {
    private val libraryLoaded: Boolean = runCatching {
        System.loadLibrary("android_app")
        true
    }.getOrElse { false }

    @JvmStatic
    external fun putObject(baseUrl: String, key: String, payload: ByteArray): Int

    @JvmStatic
    external fun getObject(baseUrl: String, key: String): ByteArray

    fun isAvailable(): Boolean = libraryLoaded
}
