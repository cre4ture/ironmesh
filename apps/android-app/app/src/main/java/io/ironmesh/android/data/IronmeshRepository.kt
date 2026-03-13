package io.ironmesh.android.data

import io.ironmesh.android.api.ClientDeviceEnrollRequest
import io.ironmesh.android.api.ClientDeviceEnrollResponse
import io.ironmesh.android.api.HealthResponse
import io.ironmesh.android.api.IronmeshApi
import io.ironmesh.android.api.ReplicationPlanResponse
import io.ironmesh.android.api.StoreIndexEntry
import io.ironmesh.android.api.StoreIndexResponse
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Request
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import java.net.URL
import java.io.OutputStream
import java.io.InputStream

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

    private fun createHttpClient(authToken: String? = null): OkHttpClient {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }

        return OkHttpClient.Builder()
            .addInterceptor { chain ->
                val request = if (!authToken.isNullOrBlank()) {
                    chain.request()
                        .newBuilder()
                        .header("Authorization", "Bearer $authToken")
                        .build()
                } else {
                    chain.request()
                }
                chain.proceed(request)
            }
            .addInterceptor(logging)
            .build()
    }

    private fun createApi(baseUrl: String, authToken: String? = null): IronmeshApi {
        val moshi = Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()

        return Retrofit.Builder()
            .baseUrl(sanitizeBaseUrl(baseUrl))
            .client(createHttpClient(authToken))
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()
            .create(IronmeshApi::class.java)
    }

    private fun shouldUseRustBridge(): Boolean {
        return RustClientBridge.isAvailable()
    }

    private fun <T> decodeJson(json: String, clazz: Class<T>): T {
        val adapter = Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()
            .adapter(clazz)
        return adapter.fromJson(json)
            ?: throw IllegalStateException("failed to decode ${clazz.simpleName}")
    }

    suspend fun health(baseUrl: String, authToken: String? = null): HealthResponse {
        return createApi(baseUrl, authToken).health()
    }

    suspend fun replicationPlan(baseUrl: String, authToken: String? = null): ReplicationPlanResponse {
        return createApi(baseUrl, authToken).replicationPlan()
    }

    suspend fun enrollDevice(
        baseUrl: String,
        pairingToken: String,
        deviceId: String? = null,
        label: String? = null,
    ): ClientDeviceEnrollResponse {
        if (shouldUseRustBridge()) {
            return decodeJson(
                RustClientBridge.enrollDevice(
                    sanitizeBaseUrl(baseUrl),
                    pairingToken,
                    deviceId,
                    label,
                ),
                ClientDeviceEnrollResponse::class.java,
            )
        }

        val response = createApi(baseUrl).enrollDevice(
            ClientDeviceEnrollRequest(
                pairing_token = pairingToken,
                device_id = deviceId,
                label = label,
            ),
        )
        if (!response.isSuccessful) {
            throw IllegalStateException("Enroll failed with HTTP ${response.code()}")
        }
        return response.body() ?: throw IllegalStateException("Enroll failed: empty response body")
    }

    suspend fun putObject(baseUrl: String, key: String, payload: String, authToken: String? = null): Int {
        if (!shouldUseRustBridge()) {
            return putObjectBytes(baseUrl, key, payload.toByteArray(Charsets.UTF_8), authToken)
        }
        return RustClientBridge.putObject(
            sanitizeBaseUrl(baseUrl),
            key,
            payload.toByteArray(Charsets.UTF_8),
            authToken,
        )
    }

    suspend fun getObject(
        baseUrl: String,
        key: String,
        snapshot: String? = null,
        version: String? = null,
        authToken: String? = null,
    ): String {
        val bytes = getObjectBytes(baseUrl, key, snapshot, version, authToken)
        return bytes.toString(Charsets.UTF_8)
    }

    suspend fun storeIndex(
        baseUrl: String,
        prefix: String? = null,
        depth: Int = 1,
        snapshot: String? = null,
        authToken: String? = null,
    ): List<StoreIndexEntry> {
        if (!shouldUseRustBridge()) {
            return createApi(baseUrl, authToken).storeIndex(
                prefix = prefix,
                depth = depth.coerceAtLeast(1),
                snapshot = snapshot,
            ).entries
        }

        val responseJson = RustClientBridge.storeIndex(
            sanitizeBaseUrl(baseUrl),
            prefix,
            depth.coerceAtLeast(1),
            snapshot,
            authToken,
        )
        val parsed = decodeJson(responseJson, StoreIndexResponse::class.java)
        return parsed.entries
    }

    suspend fun putObjectBytes(
        baseUrl: String,
        key: String,
        payload: ByteArray,
        authToken: String? = null,
    ): Int {
        if (!shouldUseRustBridge()) {
            val response = createApi(baseUrl, authToken).putObject(
                key,
                payload.toRequestBody("application/octet-stream".toMediaType()),
            )
            if (!response.isSuccessful) {
                throw IllegalStateException("PUT failed with HTTP ${response.code()}")
            }
            return response.code()
        }

        return RustClientBridge.putObject(sanitizeBaseUrl(baseUrl), key, payload, authToken)
    }

    suspend fun streamPutObject(
        baseUrl: String,
        key: String,
        input: InputStream,
        authToken: String? = null,
    ): Int {
        if (!shouldUseRustBridge()) {
            val requestBody = object : RequestBody() {
                override fun contentType() = "application/octet-stream".toMediaType()

                override fun writeTo(sink: okio.BufferedSink) {
                    input.use { source ->
                        sink.outputStream().use { output ->
                            source.copyTo(output)
                        }
                    }
                }
            }
            val response = createApi(baseUrl, authToken).putObject(key, requestBody)
            if (!response.isSuccessful) {
                throw IllegalStateException("PUT failed with HTTP ${response.code()}")
            }
            return response.code()
        }

        return RustClientBridge.streamPutObject(sanitizeBaseUrl(baseUrl), key, input, authToken)
    }

    suspend fun deleteObject(baseUrl: String, key: String, authToken: String? = null): Int {
        if (shouldUseRustBridge()) {
            return RustClientBridge.deleteObject(sanitizeBaseUrl(baseUrl), key, authToken)
        }

        val response = createApi(baseUrl, authToken).deleteObject(key)
        if (!response.isSuccessful) {
            throw IllegalStateException("DELETE failed with HTTP ${response.code()}")
        }
        return response.code()
    }

    suspend fun getObjectBytes(
        baseUrl: String,
        key: String,
        snapshot: String? = null,
        version: String? = null,
        authToken: String? = null,
    ): ByteArray {
        if (shouldUseRustBridge()) {
            return RustClientBridge.getObject(
                sanitizeBaseUrl(baseUrl),
                key,
                snapshot,
                version,
                authToken,
            )
        }

        val response = createApi(baseUrl, authToken).getObjectBinary(key, snapshot = snapshot, version = version)
        if (!response.isSuccessful) {
            throw IllegalStateException("GET failed with HTTP ${response.code()}")
        }
        return response.body()?.bytes()
            ?: throw IllegalStateException("GET failed: empty response body")
    }

    suspend fun streamObjectTo(
        baseUrl: String,
        key: String,
        output: OutputStream,
        snapshot: String? = null,
        version: String? = null,
        authToken: String? = null,
    ) {
        if (!shouldUseRustBridge()) {
            val response = createApi(baseUrl, authToken).getObjectBinary(
                key,
                snapshot = snapshot,
                version = version,
            )
            if (!response.isSuccessful) {
                throw IllegalStateException("GET failed with HTTP ${response.code()}")
            }
            val body = response.body() ?: throw IllegalStateException("GET failed: empty response body")
            body.byteStream().use { input ->
                input.copyTo(output)
            }
            return
        }

        RustClientBridge.streamObjectTo(
            sanitizeBaseUrl(baseUrl),
            key,
            output,
            snapshot,
            version,
            authToken,
        )
        return
    }

    suspend fun streamRelativeUrlTo(
        baseUrl: String,
        relativeUrl: String,
        output: OutputStream,
        authToken: String? = null,
    ) {
        val request = Request.Builder()
            .url(URL(URL(sanitizeBaseUrl(baseUrl)), relativeUrl))
            .build()

        createHttpClient(authToken).newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IllegalStateException("GET failed with HTTP ${response.code}")
            }

            val body = response.body ?: throw IllegalStateException("GET failed: empty response body")
            body.byteStream().use { input ->
                input.copyTo(output)
            }
        }
    }

    fun startWebUi(baseUrl: String, authToken: String? = null): String {
        if (!authToken.isNullOrBlank()) {
            throw IllegalStateException("Embedded Web UI is not yet wired for authenticated clusters")
        }
        if (!RustClientBridge.isAvailable()) {
            throw IllegalStateException("Rust client bridge is not available")
        }

        return RustClientBridge.startWebUi(sanitizeBaseUrl(baseUrl))
    }
}
