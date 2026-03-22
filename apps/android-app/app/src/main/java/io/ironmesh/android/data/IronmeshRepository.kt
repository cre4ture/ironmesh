package io.ironmesh.android.data

import io.ironmesh.android.api.StoreIndexEntry
import io.ironmesh.android.api.StoreIndexResponse
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.io.InputStream
import java.io.OutputStream

data class BootstrapEnrollmentData(
    val cluster_id: String,
    val connection_bootstrap_json: String? = null,
    val device_id: String,
    val label: String? = null,
    val public_key_pem: String,
    val private_key_pem: String,
    val credential_pem: String,
    val rendezvous_client_identity_pem: String? = null,
    val server_base_url: String? = null,
    val server_ca_pem: String? = null,
)

class IronmeshRepository {
    private fun normalizedClientIdentityJson(clientIdentityJson: String?): String? {
        return clientIdentityJson?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun normalizedConnectionInput(connectionInput: String): String {
        val trimmed = connectionInput.trim()
        return if (trimmed.startsWith("{")) trimmed else sanitizeBaseUrl(trimmed)
    }

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
            clusterId = enrolled.cluster_id,
            deviceId = enrolled.device_id,
            label = enrolled.label,
            connectionBootstrapJson = enrolled.connection_bootstrap_json?.trim().orEmpty(),
            directServerBaseUrl = enrolled.server_base_url.orEmpty(),
            serverCaPem = enrolled.server_ca_pem,
            publicKeyPem = enrolled.public_key_pem,
            privateKeyPem = enrolled.private_key_pem,
            credentialPem = enrolled.credential_pem,
            rendezvousClientIdentityPem = enrolled.rendezvous_client_identity_pem,
        )
    }

    suspend fun putObject(
        connectionInput: String,
        key: String,
        payload: String,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ): Int {
        return RustClientBridge.putObject(
            normalizedConnectionInput(connectionInput),
            key,
            payload.toByteArray(Charsets.UTF_8),
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
    }

    suspend fun getObject(
        connectionInput: String,
        key: String,
        snapshot: String? = null,
        version: String? = null,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ): String {
        val bytes = getObjectBytes(
            connectionInput,
            key,
            snapshot,
            version,
            serverCaPem,
            clientIdentityJson,
        )
        return bytes.toString(Charsets.UTF_8)
    }

    suspend fun storeIndex(
        connectionInput: String,
        prefix: String? = null,
        depth: Int = 1,
        snapshot: String? = null,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ): List<StoreIndexEntry> {
        val responseJson = RustClientBridge.storeIndex(
            normalizedConnectionInput(connectionInput),
            prefix,
            depth.coerceAtLeast(1),
            snapshot,
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
        val parsed = decodeJson(responseJson, StoreIndexResponse::class.java)
        return parsed.entries
    }

    suspend fun putObjectBytes(
        connectionInput: String,
        key: String,
        payload: ByteArray,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ): Int {
        return RustClientBridge.putObject(
            normalizedConnectionInput(connectionInput),
            key,
            payload,
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
    }

    suspend fun streamPutObject(
        connectionInput: String,
        key: String,
        input: InputStream,
        sizeBytes: Long,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ): Int {
        return RustClientBridge.streamPutObject(
            normalizedConnectionInput(connectionInput),
            key,
            input,
            sizeBytes,
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
    }

    suspend fun deleteObject(
        connectionInput: String,
        key: String,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ): Int {
        return RustClientBridge.deleteObject(
            normalizedConnectionInput(connectionInput),
            key,
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
    }

    suspend fun getObjectBytes(
        connectionInput: String,
        key: String,
        snapshot: String? = null,
        version: String? = null,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ): ByteArray {
        return RustClientBridge.getObject(
            normalizedConnectionInput(connectionInput),
            key,
            snapshot,
            version,
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
    }

    suspend fun streamObjectTo(
        connectionInput: String,
        key: String,
        output: OutputStream,
        snapshot: String? = null,
        version: String? = null,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ) {
        RustClientBridge.streamObjectTo(
            normalizedConnectionInput(connectionInput),
            key,
            output,
            snapshot,
            version,
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
    }

    suspend fun streamRelativeUrlTo(
        connectionInput: String,
        relativeUrl: String,
        output: OutputStream,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ) {
        RustClientBridge.streamRelativeUrlTo(
            normalizedConnectionInput(connectionInput),
            relativeUrl,
            output,
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
    }

    fun startWebUi(
        connectionInput: String,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ): String {
        return RustClientBridge.startWebUi(
            normalizedConnectionInput(connectionInput),
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
    }

    suspend fun runFolderSyncOnce(
        connectionInput: String,
        localFolder: String,
        localFolderTreeUri: String? = null,
        prefix: String? = null,
        depth: Int = 64,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ) {
        RustClientBridge.runFolderSyncOnce(
            normalizedConnectionInput(connectionInput),
            localFolder,
            localFolderTreeUri,
            prefix,
            depth.coerceAtLeast(1),
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
        )
    }

    fun startContinuousFolderSync(
        profileId: String,
        label: String,
        connectionInput: String,
        localFolder: String,
        localFolderTreeUri: String? = null,
        prefix: String? = null,
        depth: Int = 64,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ) {
        RustClientBridge.startContinuousFolderSync(
            profileId,
            label,
            normalizedConnectionInput(connectionInput),
            localFolder,
            localFolderTreeUri,
            prefix,
            depth.coerceAtLeast(1),
            serverCaPem,
            normalizedClientIdentityJson(clientIdentityJson),
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
