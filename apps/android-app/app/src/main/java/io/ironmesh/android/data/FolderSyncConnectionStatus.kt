package io.ironmesh.android.data

const val FOLDER_SYNC_CONNECTION_STATE_STOPPED = "stopped"
const val FOLDER_SYNC_CONNECTION_STATE_CONNECTING = "connecting"
const val FOLDER_SYNC_CONNECTION_STATE_CONNECTED = "connected"
const val FOLDER_SYNC_CONNECTION_STATE_RECONNECTING = "reconnecting"
const val FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_NETWORK = "waiting-for-network"
const val FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_ENROLLMENT = "waiting-for-enrollment"
const val FOLDER_SYNC_CONNECTION_STATE_RETRY_SCHEDULED = "retry-scheduled"
const val FOLDER_SYNC_CONNECTION_STATE_ERROR = "error"

private const val RETRY_BASE_DELAY_MS = 2_000L
private const val RETRY_MAX_DELAY_MS = 60_000L

data class FolderSyncConnectionStatus(
    val state: String = FOLDER_SYNC_CONNECTION_STATE_STOPPED,
    val message: String = "Continuous sync is stopped",
    val updatedUnixMs: Long = 0L,
    val retryAttemptCount: Long = 0L,
    val nextRetryUnixMs: Long? = null,
)

fun nextFolderSyncRetryDelayMs(attempt: Int): Long {
    if (attempt <= 1) {
        return RETRY_BASE_DELAY_MS
    }
    val exponent = (attempt - 1).coerceAtMost(5)
    val multiplier = 1L shl exponent
    return (RETRY_BASE_DELAY_MS * multiplier).coerceAtMost(RETRY_MAX_DELAY_MS)
}

fun FolderSyncConnectionStatus.isRetryPending(): Boolean {
    return state == FOLDER_SYNC_CONNECTION_STATE_RETRY_SCHEDULED || nextRetryUnixMs != null
}

fun FolderSyncConnectionStatus.isConnected(): Boolean {
    return state == FOLDER_SYNC_CONNECTION_STATE_CONNECTED
}
