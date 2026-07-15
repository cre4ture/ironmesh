package io.ironmesh.android.data

const val APP_CONNECTION_STATE_STOPPED = "stopped"
const val APP_CONNECTION_STATE_CONNECTING = "connecting"
const val APP_CONNECTION_STATE_CONNECTED = "connected"
const val APP_CONNECTION_STATE_RECONNECTING = "reconnecting"
const val APP_CONNECTION_STATE_WAITING_FOR_NETWORK = "waiting-for-network"
const val APP_CONNECTION_STATE_WAITING_FOR_ENROLLMENT = "waiting-for-enrollment"
const val APP_CONNECTION_STATE_RETRY_SCHEDULED = "retry-scheduled"
const val APP_CONNECTION_STATE_ERROR = "error"

private const val RETRY_BASE_DELAY_MS = 2_000L
private const val RETRY_MAX_DELAY_MS = 60_000L

// App-wide connection status shared by sync, gallery, and other foreground requests.
data class AppConnectionStatus(
    val state: String = APP_CONNECTION_STATE_STOPPED,
    val message: String = "No app connection activity yet",
    val updatedUnixMs: Long = 0L,
    val retryAttemptCount: Long = 0L,
    val nextRetryUnixMs: Long? = null,
    val lastSuccessfulConnectionUnixMs: Long? = null,
    val lastSuccessfulConnectionUrl: String? = null,
    val failedAttempts: List<AppFailedConnectionAttempt> = emptyList(),
)

data class AppFailedConnectionAttempt(
    val sourceLabel: String? = null,
    val endpointLocator: String = "",
    val pathKind: String = "",
    val startedUnixMs: Long = 0L,
    val finishedUnixMs: Long? = null,
    val method: String = "",
    val url: String = "",
    val timeoutMs: Long? = null,
    val error: String? = null,
)

data class AppConnectionDiagnosticsUpdate(
    val sourceLabel: String? = null,
    val lastSuccessfulConnectionUnixMs: Long? = null,
    val lastSuccessfulConnectionUrl: String? = null,
    val failedAttempts: List<AppFailedConnectionAttempt> = emptyList(),
)

fun nextAppConnectionRetryDelayMs(attempt: Int): Long {
    if (attempt <= 1) {
        return RETRY_BASE_DELAY_MS
    }
    val exponent = (attempt - 1).coerceAtMost(5)
    val multiplier = 1L shl exponent
    return (RETRY_BASE_DELAY_MS * multiplier).coerceAtMost(RETRY_MAX_DELAY_MS)
}

fun AppConnectionStatus.isRetryPending(): Boolean {
    return state == APP_CONNECTION_STATE_RETRY_SCHEDULED || nextRetryUnixMs != null
}

fun AppConnectionStatus.isConnected(): Boolean {
    return state == APP_CONNECTION_STATE_CONNECTED
}
