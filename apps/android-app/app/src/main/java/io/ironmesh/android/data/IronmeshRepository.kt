package io.ironmesh.android.data

import io.ironmesh.android.api.StoreIndexEntry
import io.ironmesh.android.api.StoreIndexResponse
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.io.InputStream
import java.io.OutputStream

data class BootstrapEnrollmentData(
    val server_base_url: String,
    val server_ca_pem: String? = null,
    val device_id: String,
    val device_token: String,
    val label: String? = null,
)

class IronmeshRepository {
    fun sanitizeBaseUrl(input: String): String {
        val trimmed = input.trim()
        val withScheme = if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            trimmed
        } else {
            "http://$trimmed"
        }
        return if (withScheme.endsWith('/')) withScheme else "$withScheme/"
    }

    private fun <T> decodeJson(json: String, clazz: Class<T>): T {
        val adapter = Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()
            .adapter(clazz)
        return adapter.fromJson(json)
            ?: throw IllegalStateException("failed to decode ${clazz.simpleName}")
    }

    suspend fun enrollWithBootstrap(
        bootstrapJson: String,
        deviceId: String? = null,
        label: String? = null,
    ): DeviceAuthState {
        val enrolled = decodeJson(
            RustClientBridge.enrollWithBootstrap(bootstrapJson, deviceId, label),
            BootstrapEnrollmentData::class.java,
        )
        return DeviceAuthState(
            deviceId = enrolled.device_id,
            deviceToken = enrolled.device_token,
            label = enrolled.label,
            serverBaseUrl = enrolled.server_base_url,
            serverCaPem = enrolled.server_ca_pem,
        )
    }

    suspend fun putObject(
        baseUrl: String,
        key: String,
        payload: String,
        serverCaPem: String? = null,
        authToken: String? = null,
    ): Int {
        return RustClientBridge.putObject(
            sanitizeBaseUrl(baseUrl),
            key,
            payload.toByteArray(Charsets.UTF_8),
            serverCaPem,
            authToken,
        )
    }

    suspend fun getObject(
        baseUrl: String,
        key: String,
        snapshot: String? = null,
        version: String? = null,
        serverCaPem: String? = null,
        authToken: String? = null,
    ): String {
        val bytes = getObjectBytes(baseUrl, key, snapshot, version, serverCaPem, authToken)
        return bytes.toString(Charsets.UTF_8)
    }

    suspend fun storeIndex(
        baseUrl: String,
        prefix: String? = null,
        depth: Int = 1,
        snapshot: String? = null,
        serverCaPem: String? = null,
        authToken: String? = null,
    ): List<StoreIndexEntry> {
        val responseJson = RustClientBridge.storeIndex(
            sanitizeBaseUrl(baseUrl),
            prefix,
            depth.coerceAtLeast(1),
            snapshot,
            serverCaPem,
            authToken,
        )
        val parsed = decodeJson(responseJson, StoreIndexResponse::class.java)
        return parsed.entries
    }

    suspend fun putObjectBytes(
        baseUrl: String,
        key: String,
        payload: ByteArray,
        serverCaPem: String? = null,
        authToken: String? = null,
    ): Int {
        return RustClientBridge.putObject(
            sanitizeBaseUrl(baseUrl),
            key,
            payload,
            serverCaPem,
            authToken,
        )
    }

    suspend fun streamPutObject(
        baseUrl: String,
        key: String,
        input: InputStream,
        serverCaPem: String? = null,
        authToken: String? = null,
    ): Int {
        return RustClientBridge.streamPutObject(
            sanitizeBaseUrl(baseUrl),
            key,
            input,
            serverCaPem,
            authToken,
        )
    }

    suspend fun deleteObject(
        baseUrl: String,
        key: String,
        serverCaPem: String? = null,
        authToken: String? = null,
    ): Int {
        return RustClientBridge.deleteObject(
            sanitizeBaseUrl(baseUrl),
            key,
            serverCaPem,
            authToken,
        )
    }

    suspend fun getObjectBytes(
        baseUrl: String,
        key: String,
        snapshot: String? = null,
        version: String? = null,
        serverCaPem: String? = null,
        authToken: String? = null,
    ): ByteArray {
        return RustClientBridge.getObject(
            sanitizeBaseUrl(baseUrl),
            key,
            snapshot,
            version,
            serverCaPem,
            authToken,
        )
    }

    suspend fun streamObjectTo(
        baseUrl: String,
        key: String,
        output: OutputStream,
        snapshot: String? = null,
        version: String? = null,
        serverCaPem: String? = null,
        authToken: String? = null,
    ) {
        RustClientBridge.streamObjectTo(
            sanitizeBaseUrl(baseUrl),
            key,
            output,
            snapshot,
            version,
            serverCaPem,
            authToken,
        )
    }

    suspend fun streamRelativeUrlTo(
        baseUrl: String,
        relativeUrl: String,
        output: OutputStream,
        serverCaPem: String? = null,
        authToken: String? = null,
    ) {
        RustClientBridge.streamRelativeUrlTo(
            sanitizeBaseUrl(baseUrl),
            relativeUrl,
            output,
            serverCaPem,
            authToken,
        )
    }

    fun startWebUi(baseUrl: String, authToken: String? = null): String {
        if (!authToken.isNullOrBlank()) {
            throw IllegalStateException("Embedded Web UI is not yet wired for authenticated clusters")
        }
        return RustClientBridge.startWebUi(sanitizeBaseUrl(baseUrl))
    }

    suspend fun runFolderSyncOnce(
        baseUrl: String,
        localFolder: String,
        localFolderTreeUri: String? = null,
        prefix: String? = null,
        depth: Int = 64,
        serverCaPem: String? = null,
        authToken: String? = null,
    ) {
        RustClientBridge.runFolderSyncOnce(
            sanitizeBaseUrl(baseUrl),
            localFolder,
            localFolderTreeUri,
            prefix,
            depth.coerceAtLeast(1),
            serverCaPem,
            authToken,
        )
    }

    fun startContinuousFolderSync(
        profileId: String,
        label: String,
        baseUrl: String,
        localFolder: String,
        localFolderTreeUri: String? = null,
        prefix: String? = null,
        depth: Int = 64,
        serverCaPem: String? = null,
        authToken: String? = null,
    ) {
        RustClientBridge.startContinuousFolderSync(
            profileId,
            label,
            sanitizeBaseUrl(baseUrl),
            localFolder,
            localFolderTreeUri,
            prefix,
            depth.coerceAtLeast(1),
            serverCaPem,
            authToken,
        )
    }

    fun stopContinuousFolderSync(profileId: String) {
        RustClientBridge.stopContinuousFolderSync(profileId)
    }

    fun stopAllContinuousFolderSync() {
        RustClientBridge.stopAllContinuousFolderSync()
    }

    fun getContinuousFolderSyncStatus(): FolderSyncServiceStatus {
        return decodeJson(
            RustClientBridge.getContinuousFolderSyncStatus(),
            FolderSyncServiceStatus::class.java,
        )
    }

    fun hasContinuousFolderSyncActive(): Boolean {
        return RustClientBridge.hasContinuousFolderSyncActive()
    }
}
