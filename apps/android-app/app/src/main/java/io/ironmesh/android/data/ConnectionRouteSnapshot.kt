package io.ironmesh.android.data

import com.squareup.moshi.Json

data class ConnectionRouteSnapshot(
    @Json(name = "generated_at_unix_ms")
    val generatedAtUnixMs: Long,
    @Json(name = "active_index")
    val activeIndex: Int? = null,
    @Json(name = "ranked_indices")
    val rankedIndices: List<Int> = emptyList(),
    val endpoints: List<ConnectionRouteEndpointSnapshot> = emptyList(),
)

data class ConnectionRouteEndpointSnapshot(
    val index: Int,
    @Json(name = "path_kind")
    val pathKind: String,
    val locator: String,
    @Json(name = "bootstrap_rank")
    val bootstrapRank: Int,
    @Json(name = "target_node_id")
    val targetNodeId: String? = null,
    val active: Boolean,
    val score: Double,
    @Json(name = "ewma_latency_ms")
    val ewmaLatencyMs: Double? = null,
    @Json(name = "ewma_throughput_bytes_per_sec")
    val ewmaThroughputBytesPerSec: Double? = null,
    @Json(name = "consecutive_failures")
    val consecutiveFailures: Int,
    @Json(name = "total_failures")
    val totalFailures: Long,
    @Json(name = "total_successes")
    val totalSuccesses: Long,
    @Json(name = "last_measurement_unix_ms")
    val lastMeasurementUnixMs: Long? = null,
    @Json(name = "last_success_unix_ms")
    val lastSuccessUnixMs: Long? = null,
    @Json(name = "last_failure_unix_ms")
    val lastFailureUnixMs: Long? = null,
    @Json(name = "circuit_open_until_unix_ms")
    val circuitOpenUntilUnixMs: Long? = null,
    @Json(name = "background_probe_in_flight")
    val backgroundProbeInFlight: Boolean,
    @Json(name = "last_background_probe_unix_ms")
    val lastBackgroundProbeUnixMs: Long? = null,
    @Json(name = "last_error")
    val lastError: String? = null,
)
