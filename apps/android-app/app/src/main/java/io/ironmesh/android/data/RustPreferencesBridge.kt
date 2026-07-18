package io.ironmesh.android.data

import android.content.Context
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import org.json.JSONObject

object RustPreferencesBridge {
    private const val MAX_FAILED_CONNECTION_ATTEMPTS = 12

    @Volatile
    private var appContext: Context? = null

    private val diagnosticsUpdateAdapter by lazy {
        Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()
            .adapter(AppConnectionDiagnosticsUpdate::class.java)
    }

    @JvmStatic
    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    @JvmStatic
    @Throws(DeviceIdentityStorageException::class)
    fun updateDeviceAuthBootstrapJson(bootstrapJson: String) {
        val context = appContext ?: error("RustPreferencesBridge is not initialized")
        val current = IronmeshPreferences.getDeviceAuthState(context)
        IronmeshPreferences.setDeviceAuthState(
            context,
            current.copy(connectionBootstrapJson = bootstrapJson.trim()),
        )
    }

    @JvmStatic
    @Throws(DeviceIdentityStorageException::class)
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
                credentialPem = json.requiredTrimmedString("credential_pem"),
                rendezvousClientIdentityPem =
                    json.optionalTrimmedString("rendezvous_client_identity_pem"),
            ),
        )
    }

    @JvmStatic
    fun updateAppConnectionDiagnosticsJson(diagnosticsJson: String) {
        val context = appContext ?: error("RustPreferencesBridge is not initialized")
        val update = diagnosticsUpdateAdapter.fromJson(diagnosticsJson) ?: return
        val current = IronmeshPreferences.getAppConnectionStatus(context)
        val mergedFailures = (current.failedAttempts + update.failedAttempts)
            .distinctBy { attempt -> failedAttemptKey(attempt) }
            .sortedByDescending { attempt -> attempt.finishedUnixMs ?: attempt.startedUnixMs }
            .take(MAX_FAILED_CONNECTION_ATTEMPTS)

        val effectiveLastSuccessUnixMs = when {
            current.lastSuccessfulConnectionUnixMs == null -> update.lastSuccessfulConnectionUnixMs
            update.lastSuccessfulConnectionUnixMs == null -> current.lastSuccessfulConnectionUnixMs
            update.lastSuccessfulConnectionUnixMs >= current.lastSuccessfulConnectionUnixMs ->
                update.lastSuccessfulConnectionUnixMs
            else -> current.lastSuccessfulConnectionUnixMs
        }
        val effectiveLastSuccessUrl = when {
            effectiveLastSuccessUnixMs == null -> null
            effectiveLastSuccessUnixMs == update.lastSuccessfulConnectionUnixMs ->
                update.lastSuccessfulConnectionUrl?.takeIf { it.isNotBlank() }
                    ?: current.lastSuccessfulConnectionUrl
            else -> current.lastSuccessfulConnectionUrl
        }

        val latestFailure = mergedFailures.maxByOrNull { attempt ->
            attempt.finishedUnixMs ?: attempt.startedUnixMs
        }
        val latestFailureUnixMs = latestFailure?.finishedUnixMs ?: latestFailure?.startedUnixMs
        val latestSuccessUnixMs = effectiveLastSuccessUnixMs
        val latestEventUnixMs = listOfNotNull(latestSuccessUnixMs, latestFailureUnixMs).maxOrNull()

        val shouldRefreshState = latestEventUnixMs != null && latestEventUnixMs >= current.updatedUnixMs
        val nextState = when {
            !shouldRefreshState -> current.state
            latestSuccessUnixMs != null &&
                latestSuccessUnixMs >= (latestFailureUnixMs ?: Long.MIN_VALUE) ->
                APP_CONNECTION_STATE_CONNECTED
            latestFailureUnixMs != null -> APP_CONNECTION_STATE_ERROR
            else -> current.state
        }
        val nextMessage = when {
            !shouldRefreshState -> current.message
            nextState == APP_CONNECTION_STATE_CONNECTED && !effectiveLastSuccessUrl.isNullOrBlank() ->
                "Last request succeeded via $effectiveLastSuccessUrl"
            nextState == APP_CONNECTION_STATE_CONNECTED ->
                "Last app request succeeded"
            nextState == APP_CONNECTION_STATE_ERROR ->
                latestFailure?.error?.takeIf { it.isNotBlank() }
                    ?: "Last app request failed"
            else -> current.message
        }

        IronmeshPreferences.setAppConnectionStatus(
            context,
            current.copy(
                state = nextState,
                message = nextMessage,
                updatedUnixMs = latestEventUnixMs ?: current.updatedUnixMs,
                retryAttemptCount = if (shouldRefreshState) 0L else current.retryAttemptCount,
                nextRetryUnixMs = if (shouldRefreshState) null else current.nextRetryUnixMs,
                lastSuccessfulConnectionUnixMs = effectiveLastSuccessUnixMs,
                lastSuccessfulConnectionUrl = effectiveLastSuccessUrl,
                failedAttempts = mergedFailures,
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
        optionalTrimmedString(name) ?: throw DeviceIdentityStorageException(
            "The client identity update is missing $name. Clear local enrollment and enroll this device again.",
        )

    private fun failedAttemptKey(attempt: AppFailedConnectionAttempt): String {
        return listOf(
            attempt.sourceLabel.orEmpty(),
            attempt.endpointLocator,
            attempt.pathKind,
            attempt.startedUnixMs.toString(),
            attempt.finishedUnixMs?.toString().orEmpty(),
            attempt.method,
            attempt.url,
            attempt.timeoutMs?.toString().orEmpty(),
            attempt.error.orEmpty(),
        ).joinToString("|")
    }
}
