package io.ironmesh.android.api

import okhttp3.RequestBody
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
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
)
