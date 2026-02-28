package io.ironmesh.android.data

import io.ironmesh.android.api.HealthResponse
import io.ironmesh.android.api.IronmeshApi
import io.ironmesh.android.api.ReplicationPlanResponse
import io.ironmesh.android.api.StoreIndexEntry
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody
import okio.source
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import java.io.OutputStream

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

    private fun createApi(baseUrl: String): IronmeshApi {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }

        val client = OkHttpClient.Builder()
            .addInterceptor(logging)
            .build()

        val moshi = Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()

        return Retrofit.Builder()
            .baseUrl(sanitizeBaseUrl(baseUrl))
            .client(client)
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()
            .create(IronmeshApi::class.java)
    }

    suspend fun health(baseUrl: String): HealthResponse {
        return createApi(baseUrl).health()
    }

    suspend fun replicationPlan(baseUrl: String): ReplicationPlanResponse {
        return createApi(baseUrl).replicationPlan()
    }

    suspend fun putObject(baseUrl: String, key: String, payload: String): Int {
        if (!RustClientBridge.isAvailable()) {
            throw IllegalStateException("Rust client bridge is not available")
        }

        return RustClientBridge.putObject(
            sanitizeBaseUrl(baseUrl),
            key,
            payload.toByteArray(Charsets.UTF_8),
        )
    }

    suspend fun getObject(
        baseUrl: String,
        key: String,
        snapshot: String? = null,
        version: String? = null,
    ): String {
        if (!RustClientBridge.isAvailable()) {
            throw IllegalStateException("Rust client bridge is not available")
        }

        return RustClientBridge.getObject(
            sanitizeBaseUrl(baseUrl),
            key,
            snapshot,
            version,
        )
            .toString(Charsets.UTF_8)
    }

    suspend fun storeIndex(
        baseUrl: String,
        prefix: String? = null,
        depth: Int = 1,
        snapshot: String? = null,
    ): List<StoreIndexEntry> {
        return createApi(baseUrl)
            .storeIndex(prefix = prefix, depth = depth, snapshot = snapshot)
            .entries
    }

    suspend fun putObjectBytes(baseUrl: String, key: String, payload: ByteArray): Int {
        if (!RustClientBridge.isAvailable()) {
            throw IllegalStateException("Rust client bridge is not available")
        }

        return RustClientBridge.putObject(sanitizeBaseUrl(baseUrl), key, payload)
    }

    suspend fun streamPutObject(
        baseUrl: String,
        key: String,
        input: java.io.InputStream,
    ): Int {
        val body = object : RequestBody() {
            override fun contentType() = "application/octet-stream".toMediaTypeOrNull()

            override fun writeTo(sink: okio.BufferedSink) {
                input.source().use { source ->
                    sink.writeAll(source)
                }
            }
        }

        val response = createApi(baseUrl).putObject(key, body)
        if (!response.isSuccessful) {
            throw IllegalStateException("PUT failed with HTTP ${response.code()}")
        }
        return response.code()
    }

    suspend fun getObjectBytes(
        baseUrl: String,
        key: String,
        snapshot: String? = null,
        version: String? = null,
    ): ByteArray {
        if (RustClientBridge.isAvailable()) {
            return RustClientBridge.getObject(
                sanitizeBaseUrl(baseUrl),
                key,
                snapshot,
                version,
            )
        }

        val response = createApi(baseUrl).getObjectBinary(key, snapshot = snapshot, version = version)
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
    ) {
        val response = createApi(baseUrl).getObjectBinary(key, snapshot = snapshot, version = version)
        if (!response.isSuccessful) {
            throw IllegalStateException("GET failed with HTTP ${response.code()}")
        }
        val body = response.body() ?: throw IllegalStateException("GET failed: empty response body")
        body.byteStream().use { input ->
            input.copyTo(output)
        }
    }
}
