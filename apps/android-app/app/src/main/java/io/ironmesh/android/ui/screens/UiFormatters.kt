package io.ironmesh.android.ui.screens

import io.ironmesh.android.data.FolderSyncModificationRecord
import io.ironmesh.android.data.FolderSyncConnectionStatus
import io.ironmesh.android.data.FolderSyncFailedConnectionAttempt
import io.ironmesh.android.data.FolderSyncNetworkPolicy
import io.ironmesh.android.data.FolderSyncProfileStatus
import io.ironmesh.android.data.FolderSyncRuntimeMetrics
import io.ironmesh.android.data.FolderSyncServiceStatus
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_CONNECTED
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_CONNECTING
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_RECONNECTING
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_RETRY_SCHEDULED
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_ENROLLMENT
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_NETWORK
import io.ironmesh.android.data.formatAllowedWifiSsidsInput
import io.ironmesh.android.data.isRetryPending
import io.ironmesh.android.ui.FolderSyncActivityFilter
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

fun displayStatusToken(value: String): String {
    if (value.isBlank()) {
        return "Unknown"
    }
    return value
        .replace('-', ' ')
        .replace('_', ' ')
        .split(' ')
        .filter { it.isNotBlank() }
        .joinToString(" ") { part ->
            part.lowercase().replaceFirstChar { ch ->
                if (ch.isLowerCase()) ch.titlecase() else ch.toString()
            }
        }
}

fun folderSyncConnectionHeadline(
    connectionStatus: FolderSyncConnectionStatus,
    serviceStatus: FolderSyncServiceStatus,
    hasProfiles: Boolean,
): String {
    if (!hasProfiles) {
        return "Set up your first sync profile"
    }
    return when (connectionStatus.state) {
        FOLDER_SYNC_CONNECTION_STATE_CONNECTING -> "Connecting sync service"
        FOLDER_SYNC_CONNECTION_STATE_RECONNECTING -> "Reconnecting sync service"
        FOLDER_SYNC_CONNECTION_STATE_RETRY_SCHEDULED -> "Retry scheduled"
        FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_NETWORK -> "Waiting for network"
        FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_ENROLLMENT -> "Enrollment needed"
        FOLDER_SYNC_CONNECTION_STATE_CONNECTED -> "Sync is healthy"
        else -> serviceStatus.serviceMessage.ifBlank { "Sync needs attention" }
    }
}

fun folderSyncConnectionSummary(
    connectionStatus: FolderSyncConnectionStatus,
    serviceStatus: FolderSyncServiceStatus,
): String {
    val parts = mutableListOf<String>()
    connectionStatus.message
        .trim()
        .takeIf { it.isNotBlank() }
        ?.let(parts::add)
    serviceStatus.currentActivity
        .trim()
        .takeIf { it.isNotBlank() && it != connectionStatus.message.trim() }
        ?.let(parts::add)
    if (connectionStatus.retryAttemptCount > 0L) {
        parts += "Retry ${connectionStatus.retryAttemptCount}"
    }
    connectionStatus.nextRetryUnixMs?.let { retryAt ->
        parts += "Next retry ${formatTimestamp(retryAt)}"
    }
    connectionStatus.lastSuccessfulConnectionUnixMs?.let { lastSuccess ->
        parts += "Last success ${formatTimestamp(lastSuccess)}"
    }
    if (parts.isEmpty()) {
        parts += serviceStatus.serviceMessage.ifBlank { "Continuous sync is stopped" }
    }
    return parts.joinToString(" | ")
}

fun shouldShowRetryConnectionAction(
    connectionStatus: FolderSyncConnectionStatus,
    hasProfiles: Boolean,
): Boolean {
    if (!hasProfiles) {
        return false
    }
    return connectionStatus.state != FOLDER_SYNC_CONNECTION_STATE_CONNECTED ||
        connectionStatus.isRetryPending()
}

fun folderSyncFailedAttemptSummary(attempt: FolderSyncFailedConnectionAttempt): String {
    val parts = mutableListOf<String>()
    parts += attempt.profileLabel
    parts += attempt.method.ifBlank { "Request" }
    parts += formatTimestamp(attempt.finishedUnixMs ?: attempt.startedUnixMs)
    attempt.timeoutMs?.let { timeoutMs ->
        parts += "Timeout ${formatDurationMillis(timeoutMs)}"
    }
    return parts.joinToString(" | ")
}

fun formatDurationMillis(durationMs: Long): String {
    val totalSeconds = (durationMs / 1000L).coerceAtLeast(1L)
    return if (totalSeconds < 60L) {
        "${totalSeconds}s"
    } else {
        val minutes = totalSeconds / 60L
        val seconds = totalSeconds % 60L
        if (seconds == 0L) {
            "${minutes}m"
        } else {
            "${minutes}m ${seconds}s"
        }
    }
}

fun profileInventorySummary(status: FolderSyncProfileStatus): String {
    val metrics = status.metrics
    return buildString {
        append("Local ${metrics.localEntryCount} entries")
        append(" (${metrics.localFileCount} files, ${metrics.localDirectoryCount} folders)")
        append(" | Remote ${metrics.remoteEntryCount} entries")
        append(" (${metrics.remoteFileCount} files, ${metrics.remoteDirectoryCount} folders)")
    }
}

fun recentWorkSummary(metrics: FolderSyncRuntimeMetrics): String? {
    val parts = mutableListOf<String>()
    if (metrics.changedPathCount > 0L) {
        parts += "${metrics.changedPathCount} path(s)"
    }
    if (metrics.uploadedFileCount > 0L) {
        parts += "${metrics.uploadedFileCount} upload(s)"
    }
    if (metrics.downloadedFileCount > 0L) {
        parts += "${metrics.downloadedFileCount} download(s)"
    }
    if (metrics.deletedRemoteFileCount > 0L) {
        parts += "${metrics.deletedRemoteFileCount} remote delete(s)"
    }
    if (metrics.removedLocalPathCount > 0L) {
        parts += "${metrics.removedLocalPathCount} local removal(s)"
    }
    if (metrics.ensuredDirectoryCount > 0L) {
        parts += "${metrics.ensuredDirectoryCount} directory update(s)"
    }
    return parts.takeIf { it.isNotEmpty() }?.joinToString(", ")
}

fun startupDetailSummary(metrics: FolderSyncRuntimeMetrics): String? {
    val parts = mutableListOf<String>()
    if (metrics.preservedLocalFileCount > 0L) {
        parts += "${metrics.preservedLocalFileCount} preserved local file(s)"
    }
    if (metrics.startupConflictCount > 0L) {
        parts += "${metrics.startupConflictCount} startup conflict(s)"
    }
    return parts.takeIf { it.isNotEmpty() }?.joinToString(", ")
}

fun folderSyncAllowedTransportLabel(policy: FolderSyncNetworkPolicy): String {
    val normalizedPolicy = policy.normalized()
    val parts = mutableListOf<String>()
    if (normalizedPolicy.allowWifi) {
        parts += "Wi-Fi"
    }
    if (normalizedPolicy.allowCellular) {
        parts += "Mobile"
    }
    if (normalizedPolicy.allowOtherConnections) {
        parts += "Other"
    }
    return parts.takeIf { it.isNotEmpty() }?.joinToString("/") ?: "Blocked"
}

fun folderSyncNetworkPolicySummary(policy: FolderSyncNetworkPolicy): String {
    val normalizedPolicy = policy.normalized()
    val parts = mutableListOf<String>()
    parts += folderSyncAllowedTransportLabel(normalizedPolicy)
    if (normalizedPolicy.allowCellular) {
        parts += if (normalizedPolicy.allowRoaming) {
            "roaming allowed"
        } else {
            "no roaming"
        }
    }
    if (normalizedPolicy.allowWifi && normalizedPolicy.allowedWifiSsids.isNotEmpty()) {
        parts += "Wi-Fi names: ${formatAllowedWifiSsidsInput(normalizedPolicy)}"
    }
    return parts.joinToString(" | ")
}

fun folderSyncActivityFilterLabel(filter: FolderSyncActivityFilter): String {
    return when (filter) {
        FolderSyncActivityFilter.ALL -> "All"
        FolderSyncActivityFilter.UPLOADS -> "Uploads"
        FolderSyncActivityFilter.DOWNLOADS -> "Downloads"
        FolderSyncActivityFilter.DELETES -> "Deletes"
    }
}

fun folderSyncHistoryMatchesFilter(
    record: FolderSyncModificationRecord,
    filter: FolderSyncActivityFilter,
): Boolean {
    return when (filter) {
        FolderSyncActivityFilter.ALL -> true
        FolderSyncActivityFilter.UPLOADS -> record.operation == "upload"
        FolderSyncActivityFilter.DOWNLOADS -> record.operation == "download"
        FolderSyncActivityFilter.DELETES ->
            record.operation == "delete-local" || record.operation == "delete-remote"
    }
}

fun folderSyncOperationLabel(operation: String): String {
    return when (operation) {
        "upload" -> "Upload"
        "download" -> "Download"
        "delete-local" -> "Delete local"
        "delete-remote" -> "Delete remote"
        else -> displayStatusToken(operation)
    }
}

fun folderSyncHistorySecondaryText(record: FolderSyncModificationRecord): String? {
    val parts = mutableListOf<String>()
    record.sizeBytes?.let { sizeBytes ->
        parts += formatByteCount(sizeBytes)
    }
    if (record.phase.isNotBlank()) {
        parts += displayStatusToken(record.phase)
    }
    if (record.triggerSource.isNotBlank()) {
        parts += if (record.triggerSource == "conflict-resolution") {
            "Conflict resolution"
        } else {
            displayStatusToken(record.triggerSource)
        }
    }
    if (record.remoteKey.isNotBlank() && record.remoteKey != record.localRelativePath) {
        parts += record.remoteKey
    }
    return parts.takeIf { it.isNotEmpty() }?.joinToString(" | ")
}

fun formatByteCount(sizeBytes: Long): String {
    val kib = 1024.0
    val mib = kib * 1024.0
    return when {
        sizeBytes >= mib.toLong() -> String.format("%.1f MB", sizeBytes / mib)
        sizeBytes >= kib.toLong() -> String.format("%.1f KB", sizeBytes / kib)
        else -> "$sizeBytes B"
    }
}

fun formatTimestamp(value: Long): String {
    return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
        .withZone(ZoneId.systemDefault())
        .format(Instant.ofEpochMilli(value))
}
