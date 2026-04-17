package io.ironmesh.android.data

import android.content.Context

object RustPreferencesBridge {
    @Volatile
    private var appContext: Context? = null

    @JvmStatic
    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    @JvmStatic
    fun updateDeviceAuthBootstrapJson(bootstrapJson: String) {
        val context = appContext ?: error("RustPreferencesBridge is not initialized")
        val current = IronmeshPreferences.getDeviceAuthState(context)
        IronmeshPreferences.setDeviceAuthState(
            context,
            current.copy(connectionBootstrapJson = bootstrapJson.trim()),
        )
    }

    @JvmStatic
    fun cacheDirPath(): String {
        val context = appContext ?: error("RustPreferencesBridge is not initialized")
        return context.cacheDir.absolutePath
    }

    @JvmStatic
    fun noBackupFilesDirPath(): String {
        val context = appContext ?: error("RustPreferencesBridge is not initialized")
        return context.noBackupFilesDir.absolutePath
    }
}
