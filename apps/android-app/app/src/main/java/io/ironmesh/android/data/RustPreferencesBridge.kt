package io.ironmesh.android.data

import android.content.Context
import org.json.JSONObject

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
    fun updateDeviceAuthClientIdentityJson(clientIdentityJson: String) {
        val context = appContext ?: error("RustPreferencesBridge is not initialized")
        val current = IronmeshPreferences.getDeviceAuthState(context)
        val json = JSONObject(clientIdentityJson)
        IronmeshPreferences.setDeviceAuthState(
            context,
            current.copy(
                clusterId = json.requiredTrimmedString("cluster_id"),
                deviceId = json.requiredTrimmedString("device_id"),
                label = json.optionalTrimmedString("label"),
                publicKeyPem = json.requiredTrimmedString("public_key_pem"),
                privateKeyPem = json.requiredTrimmedString("private_key_pem"),
                credentialPem = json.optionalTrimmedString("credential_pem"),
                rendezvousClientIdentityPem =
                    json.optionalTrimmedString("rendezvous_client_identity_pem"),
            ),
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

    private fun JSONObject.optionalTrimmedString(name: String): String? {
        if (!has(name) || isNull(name)) {
            return null
        }
        return getString(name).trim().takeIf { it.isNotEmpty() }
    }

    private fun JSONObject.requiredTrimmedString(name: String): String =
        optionalTrimmedString(name) ?: error("client identity JSON is missing $name")
}
