package io.ironmesh.android.data

import io.ironmesh.android.api.HealthResponse
import io.ironmesh.android.api.IronmeshApi
import io.ironmesh.android.api.ReplicationPlanResponse
import io.ironmesh.android.api.StoreIndexEntry
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

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
        val body = payload.toRequestBody("application/octet-stream".toMediaType())
        val response = createApi(baseUrl).putObject(key, body)
        if (!response.isSuccessful) {
            throw IllegalStateException("PUT failed with HTTP ${response.code()}")
        }
        return response.code()
    }

    suspend fun getObject(baseUrl: String, key: String): String {
        return createApi(baseUrl).getObject(key).string()
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
        val body = payload.toRequestBody("application/octet-stream".toMediaType())
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
        val response = createApi(baseUrl).getObjectBinary(key, snapshot = snapshot, version = version)
        if (!response.isSuccessful) {
            throw IllegalStateException("GET failed with HTTP ${response.code()}")
        }
        return response.body()?.bytes()
            ?: throw IllegalStateException("GET failed: empty response body")
    }
}
