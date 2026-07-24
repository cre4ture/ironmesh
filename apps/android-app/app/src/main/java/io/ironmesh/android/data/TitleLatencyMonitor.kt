package io.ironmesh.android.data

import com.squareup.moshi.Json

private const val TITLE_LATENCY_DEFAULT_PERIOD_SECONDS = 30L
private const val TITLE_LATENCY_MIN_PERIOD_SECONDS = 5L
private const val TITLE_LATENCY_MAX_PERIOD_SECONDS = 3_600L

data class TitleLatencyMonitorSettings(
    val enabled: Boolean = false,
    val periodSeconds: Long = TITLE_LATENCY_DEFAULT_PERIOD_SECONDS,
) {
    fun normalized(): TitleLatencyMonitorSettings = copy(
        periodSeconds = periodSeconds.coerceIn(
            TITLE_LATENCY_MIN_PERIOD_SECONDS,
            TITLE_LATENCY_MAX_PERIOD_SECONDS,
        ),
    )
}

data class TitleLatencyProbeStatus(
    val state: String = "disabled",
    @Json(name = "connection_type")
    val connectionType: String = "unknown",
    @Json(name = "latency_ms")
    val latencyMs: Double? = null,
    @Json(name = "checked_at_unix_ms")
    val checkedAtUnixMs: Long? = null,
    val error: String? = null,
)
