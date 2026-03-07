package io.ironmesh.android.api

import okhttp3.RequestBody
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

interface IronmeshApi {
    @GET("health")
    suspend fun health(): HealthResponse

    @GET("cluster/replication/plan")
    suspend fun replicationPlan(): ReplicationPlanResponse

    @PUT("store/{key}")
    suspend fun putObject(
        @Path("key") key: String,
        @Body body: RequestBody,
    ): Response<Unit>

    @GET("store/{key}")
    suspend fun getObject(@Path("key") key: String): ResponseBody

    @GET("store/{key}")
    suspend fun getObjectBinary(
        @Path("key") key: String,
        @Query("snapshot") snapshot: String? = null,
        @Query("version") version: String? = null,
    ): Response<ResponseBody>

    @DELETE("store/{key}")
    suspend fun deleteObject(@Path("key") key: String): Response<Unit>

    @GET("store/index")
    suspend fun storeIndex(
        @Query("prefix") prefix: String? = null,
        @Query("depth") depth: Int = 1,
        @Query("snapshot") snapshot: String? = null,
    ): StoreIndexResponse
}

data class HealthResponse(
    val online: Boolean,
    val node_id: String? = null,
)

data class ReplicationPlanResponse(
    val generated_at_unix: Long,
    val under_replicated: Int,
    val over_replicated: Int,
    val items: List<ReplicationPlanItem>,
)

data class ReplicationPlanItem(
    val key: String,
)

data class StoreIndexResponse(
    val prefix: String,
    val depth: Int,
    val entry_count: Int,
    val entries: List<StoreIndexEntry>,
)

data class StoreIndexEntry(
    val path: String,
    val entry_type: String,
    val content_hash: String? = null,
    val content_fingerprint: String? = null,
    val media: StoreIndexMedia? = null,
)

data class StoreIndexMedia(
    val status: String,
    val content_fingerprint: String,
    val media_type: String? = null,
    val mime_type: String? = null,
    val width: Int? = null,
    val height: Int? = null,
    val orientation: Int? = null,
    val taken_at_unix: Long? = null,
    val gps: StoreIndexGps? = null,
    val thumbnail: StoreIndexThumbnail? = null,
    val error: String? = null,
)

data class StoreIndexGps(
    val latitude: Double,
    val longitude: Double,
)

data class StoreIndexThumbnail(
    val url: String,
    val profile: String,
    val width: Int,
    val height: Int,
    val format: String,
    val size_bytes: Long,
)
