package io.ironmesh.android.work

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.ironmesh.android.data.RustSafBridge
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_CONNECTED
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_CONNECTING
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_RECONNECTING
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_RETRY_SCHEDULED
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_STOPPED
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_ENROLLMENT
import io.ironmesh.android.data.FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_NETWORK
import io.ironmesh.android.data.FolderSyncStorageDiagnosticsHelper
import io.ironmesh.android.data.FolderSyncConnectionStatus
import io.ironmesh.android.data.FolderSyncFailedConnectionAttempt
import io.ironmesh.android.data.FolderSyncServiceStatus
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import io.ironmesh.android.data.RustPreferencesBridge
import io.ironmesh.android.data.nextFolderSyncRetryDelayMs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

class FolderSyncForegroundService : Service() {

    private val repository = IronmeshRepository()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val reconcileMutex = Mutex()
    private var statusJob: Job? = null
    private var lastLoggedStatusLine: String? = null
    private var lastDesiredSignature: String? = null
    private var waitingSummary: String? = null
    private var waitingState: String? = null
    private var retryJob: Job? = null
    private var retryAttemptCount = 0L
    private var nextRetryUnixMs: Long? = null
    private var hasEstablishedConnection = false
    private var lastPublishedConnectionStatus: FolderSyncConnectionStatus? = null
    private var networkCallbackRegistered = false
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            requestReconcile("network available")
        }

        override fun onLost(network: Network) {
            requestReconcile("network lost")
        }

        override fun onCapabilitiesChanged(
            network: Network,
            networkCapabilities: NetworkCapabilities,
        ) {
            requestReconcile("network capabilities changed")
        }
    }

    override fun onCreate() {
        super.onCreate()
        RustSafBridge.initialize(applicationContext)
        RustPreferencesBridge.initialize(applicationContext)
        lastPublishedConnectionStatus = IronmeshPreferences.getFolderSyncConnectionStatus(applicationContext)
        ensureNotificationChannel()
        startForeground(
            NOTIFICATION_ID,
            buildNotification("Starting continuous sync", "Preparing folder sync runtime"),
        )
        registerNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopContinuousSyncAndSelf()
                return START_NOT_STICKY
            }
            ACTION_RETRY -> {
                retryNow("manual retry")
                return START_STICKY
            }
            else -> {
                requestReconcile("service start")
                return START_STICKY
            }
        }
    }

    override fun onDestroy() {
        statusJob?.cancel()
        retryJob?.cancel()
        unregisterNetworkCallback()
        repository.stopAllContinuousFolderSync()
        publishConnectionStatus(
            state = FOLDER_SYNC_CONNECTION_STATE_STOPPED,
            message = "Continuous sync is stopped",
            retryCount = 0L,
            nextRetryAt = null,
        )
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun publishConnectionStatus(
        state: String,
        message: String,
        retryCount: Long = retryAttemptCount,
        nextRetryAt: Long? = nextRetryUnixMs,
        lastSuccessfulConnectionUnixMs: Long? = null,
        lastSuccessfulConnectionUrl: String? = null,
        failedAttempts: List<FolderSyncFailedConnectionAttempt>? = null,
    ) {
        val normalizedMessage = message.ifBlank { "Continuous sync is stopped" }
        val previous = lastPublishedConnectionStatus
        val effectiveLastSuccessfulConnectionUnixMs =
            lastSuccessfulConnectionUnixMs ?: previous?.lastSuccessfulConnectionUnixMs
        val effectiveLastSuccessfulConnectionUrl = when {
            !lastSuccessfulConnectionUrl.isNullOrBlank() -> lastSuccessfulConnectionUrl
            effectiveLastSuccessfulConnectionUnixMs == previous?.lastSuccessfulConnectionUnixMs ->
                previous?.lastSuccessfulConnectionUrl
            else -> null
        }
        val effectiveFailedAttempts = failedAttempts ?: previous?.failedAttempts.orEmpty()
        if (
            previous != null &&
            previous.state == state &&
            previous.message == normalizedMessage &&
            previous.retryAttemptCount == retryCount &&
            previous.nextRetryUnixMs == nextRetryAt &&
            previous.lastSuccessfulConnectionUnixMs == effectiveLastSuccessfulConnectionUnixMs &&
            previous.lastSuccessfulConnectionUrl == effectiveLastSuccessfulConnectionUrl &&
            previous.failedAttempts == effectiveFailedAttempts
        ) {
            return
        }

        val snapshot = FolderSyncConnectionStatus(
            state = state,
            message = normalizedMessage,
            updatedUnixMs = System.currentTimeMillis(),
            retryAttemptCount = retryCount,
            nextRetryUnixMs = nextRetryAt,
            lastSuccessfulConnectionUnixMs = effectiveLastSuccessfulConnectionUnixMs,
            lastSuccessfulConnectionUrl = effectiveLastSuccessfulConnectionUrl,
            failedAttempts = effectiveFailedAttempts,
        )
        lastPublishedConnectionStatus = snapshot
        IronmeshPreferences.setFolderSyncConnectionStatus(applicationContext, snapshot)
    }

    private fun clearRetryState(
        resetAttempts: Boolean = false,
        resetEstablishedConnection: Boolean = false,
    ) {
        retryJob?.cancel()
        retryJob = null
        nextRetryUnixMs = null
        if (resetAttempts) {
            retryAttemptCount = 0L
        }
        if (resetEstablishedConnection) {
            hasEstablishedConnection = false
        }
    }

    private fun retryNow(reason: String) {
        clearRetryState(resetAttempts = true)
        publishConnectionStatus(
            state = connectionAttemptState(),
            message = connectionAttemptMessage(reason, 0),
            retryCount = 0L,
            nextRetryAt = null,
        )
        requestReconcile(reason)
    }

    private fun scheduleRetry(
        reason: String,
        diagnosticsSummary: ConnectionDiagnosticsSummary? = null,
    ) {
        if (retryJob?.isActive == true) {
            if (diagnosticsSummary != null) {
                publishConnectionStatus(
                    state = FOLDER_SYNC_CONNECTION_STATE_RETRY_SCHEDULED,
                    message = buildRetryMessage(reason, nextRetryUnixMs?.let { retryAt ->
                        (retryAt - System.currentTimeMillis()).coerceAtLeast(1L)
                    } ?: nextFolderSyncRetryDelayMs(retryAttemptCount.toInt().coerceAtLeast(1))),
                    retryCount = retryAttemptCount,
                    nextRetryAt = nextRetryUnixMs,
                    lastSuccessfulConnectionUnixMs = diagnosticsSummary.lastSuccessfulConnectionUnixMs,
                    lastSuccessfulConnectionUrl = diagnosticsSummary.lastSuccessfulConnectionUrl,
                    failedAttempts = diagnosticsSummary.failedAttempts,
                )
            }
            return
        }

        retryAttemptCount += 1L
        val delayMs = nextFolderSyncRetryDelayMs(retryAttemptCount.toInt())
        nextRetryUnixMs = System.currentTimeMillis() + delayMs
        publishConnectionStatus(
            state = FOLDER_SYNC_CONNECTION_STATE_RETRY_SCHEDULED,
            message = buildRetryMessage(reason, delayMs),
            retryCount = retryAttemptCount,
            nextRetryAt = nextRetryUnixMs,
            lastSuccessfulConnectionUnixMs = diagnosticsSummary?.lastSuccessfulConnectionUnixMs,
            lastSuccessfulConnectionUrl = diagnosticsSummary?.lastSuccessfulConnectionUrl,
            failedAttempts = diagnosticsSummary?.failedAttempts,
        )
        updateNotification("Retrying sync soon", buildRetryMessage(reason, delayMs))
        retryJob = scope.launch {
            delay(delayMs)
            retryJob = null
            nextRetryUnixMs = null
            publishConnectionStatus(
                state = connectionAttemptState(),
                message = connectionAttemptMessage(
                    reason = "retry attempt ${retryAttemptCount}",
                    profileCount = 0,
                ),
                retryCount = retryAttemptCount,
                nextRetryAt = null,
            )
            requestReconcile("retry attempt ${retryAttemptCount}")
        }
    }

    private fun connectionAttemptState(): String {
        return if (hasEstablishedConnection || retryAttemptCount > 0L) {
            FOLDER_SYNC_CONNECTION_STATE_RECONNECTING
        } else {
            FOLDER_SYNC_CONNECTION_STATE_CONNECTING
        }
    }

    private fun connectionAttemptMessage(
        reason: String,
        profileCount: Int,
    ): String {
        val action = if (connectionAttemptState() == FOLDER_SYNC_CONNECTION_STATE_RECONNECTING) {
            "Reconnecting"
        } else {
            "Connecting"
        }
        val profileSummary = if (profileCount > 0) {
            " for $profileCount profile(s)"
        } else {
            ""
        }
        return when {
            reason == "manual retry" -> "$action sync service now$profileSummary"
            reason.startsWith("network") -> "$action sync service after network change$profileSummary"
            reason.startsWith("retry attempt") -> "$action sync service after retry$profileSummary"
            else -> "$action sync service$profileSummary"
        }
    }

    private fun buildRetryMessage(reason: String, delayMs: Long): String {
        val normalizedReason = summarizeReason(reason)
        return "Retrying after ${formatRetryDelay(delayMs)} because $normalizedReason"
    }

    private fun formatRetryDelay(delayMs: Long): String {
        val totalSeconds = (delayMs / 1000L).coerceAtLeast(1L)
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

    private fun currentErrorMessage(status: FolderSyncServiceStatus?): String {
        return status?.profiles
            ?.firstOrNull { profile -> profile.state == "error" }
            ?.lastError
            ?.takeIf { message -> message.isNotBlank() }
            ?: status?.currentActivity?.takeIf { activity -> activity.isNotBlank() }
            ?: status?.serviceMessage?.takeIf { message -> message.isNotBlank() }
            ?: "failed to start sync"
    }

    private fun summarizeReason(reason: String): String {
        val firstLine = reason
            .lineSequence()
            .map { line -> line.trim() }
            .firstOrNull { line -> line.isNotEmpty() }
            .orEmpty()
        val normalized = firstLine.ifBlank { "connection error" }
        return if (normalized.length <= 180) {
            normalized
        } else {
            normalized.take(177) + "..."
        }
    }

    private fun connectionDiagnosticsSummary(
        status: FolderSyncServiceStatus?,
    ): ConnectionDiagnosticsSummary {
        val profiles = status?.profiles.orEmpty()
        var lastSuccessfulConnectionUnixMs: Long? = null
        var lastSuccessfulConnectionUrl: String? = null
        val failedAttempts = mutableListOf<FolderSyncFailedConnectionAttempt>()

        profiles.forEach { profile ->
            val diagnostics = profile.connectionDiagnostics ?: return@forEach
            diagnostics.endpoints.forEach { endpoint ->
                endpoint.lastSuccessUnixMs?.let { lastSuccess ->
                    if (lastSuccessfulConnectionUnixMs == null || lastSuccess >= lastSuccessfulConnectionUnixMs!!) {
                        lastSuccessfulConnectionUnixMs = lastSuccess
                        lastSuccessfulConnectionUrl = endpoint.recentAttempts
                            .asReversed()
                            .firstOrNull { attempt -> attempt.outcome == "success" }
                            ?.url
                            ?: endpoint.locator
                    }
                }
                endpoint.recentAttempts
                    .filter { attempt -> attempt.outcome == "failure" }
                    .forEach { attempt ->
                        failedAttempts += FolderSyncFailedConnectionAttempt(
                            profileLabel = profile.label,
                            endpointLocator = endpoint.locator,
                            pathKind = endpoint.pathKind,
                            startedUnixMs = attempt.startedUnixMs,
                            finishedUnixMs = attempt.finishedUnixMs,
                            method = attempt.method,
                            url = attempt.url,
                            timeoutMs = attempt.timeoutMs,
                            error = attempt.error?.let(::summarizeReason),
                        )
                    }
            }
        }

        val sortedAttempts = failedAttempts
            .sortedByDescending { attempt -> attempt.finishedUnixMs ?: attempt.startedUnixMs }
            .take(8)
        return ConnectionDiagnosticsSummary(
            lastSuccessfulConnectionUnixMs = lastSuccessfulConnectionUnixMs,
            lastSuccessfulConnectionUrl = lastSuccessfulConnectionUrl,
            failedAttempts = sortedAttempts,
        )
    }

    private data class ConnectionDiagnosticsSummary(
        val lastSuccessfulConnectionUnixMs: Long? = null,
        val lastSuccessfulConnectionUrl: String? = null,
        val failedAttempts: List<FolderSyncFailedConnectionAttempt> = emptyList(),
    )

    private suspend fun reconcileProfiles(): Boolean {
        return reconcileMutex.withLock {
            withContext(Dispatchers.IO) {
                val deviceAuth = IronmeshPreferences.getDeviceAuthState(applicationContext)
                val connectionInput = deviceAuth.preferredConnectionInput()
                val clientIdentityJson = deviceAuth.toClientIdentityJson()
                val serverCaPem = deviceAuth.serverCaPem.takeIf { !it.isNullOrBlank() }
                val profiles = IronmeshPreferences
                    .getFolderSyncConfigs(applicationContext)
                    .filter { it.enabled }

                if (profiles.isEmpty()) {
                    repository.stopAllContinuousFolderSync()
                    waitingSummary = null
                    waitingState = null
                    lastDesiredSignature = null
                    clearRetryState(
                        resetAttempts = true,
                        resetEstablishedConnection = true,
                    )
                    publishConnectionStatus(
                        state = FOLDER_SYNC_CONNECTION_STATE_STOPPED,
                        message = "Continuous sync is stopped",
                        retryCount = 0L,
                        nextRetryAt = null,
                    )
                    withContext(Dispatchers.Main) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                    return@withContext false
                }

                if (connectionInput.isBlank() || clientIdentityJson.isNullOrBlank()) {
                    clearRetryState(resetAttempts = true)
                    applyDesiredState(
                        desiredSignature = "",
                        desiredProfiles = emptyList(),
                        connectionInput = connectionInput,
                        serverCaPem = serverCaPem,
                        clientIdentityJson = clientIdentityJson,
                    )
                    waitingSummary = "Enroll this device before continuous sync can run"
                    waitingState = FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_ENROLLMENT
                    publishConnectionStatus(
                        state = FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_ENROLLMENT,
                        message = requireNotNull(waitingSummary),
                        retryCount = 0L,
                        nextRetryAt = null,
                    )
                    updateNotification("Ironmesh sync paused", requireNotNull(waitingSummary))
                    return@withContext true
                }

                val networkDecisions = FolderSyncNetworkGate.evaluateProfiles(applicationContext, profiles)
                val allowedProfiles = networkDecisions
                    .filter { evaluation -> evaluation.decision.allowed }
                    .map { evaluation -> evaluation.profile }
                val blockedProfiles = networkDecisions
                    .filterNot { evaluation -> evaluation.decision.allowed }

                blockedProfiles.forEach { evaluation ->
                    Log.i(
                        TAG,
                        "holding continuous sync profile=${evaluation.profile.id} reason=${evaluation.decision.reason}",
                    )
                }

                waitingSummary = blockedProfiles.firstOrNull()?.let { evaluation ->
                    buildWaitingSummary(
                        blockedProfileCount = blockedProfiles.size,
                        profileLabel = evaluation.profile.label,
                        reason = evaluation.decision.reason,
                    )
                }
                waitingState = if (allowedProfiles.isEmpty()) {
                    FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_NETWORK
                } else {
                    null
                }

                val desiredSignature = buildDesiredSignature(
                    connectionInput = connectionInput,
                    serverCaPem = serverCaPem,
                    clientIdentityJson = clientIdentityJson,
                    profiles = allowedProfiles,
                )
                applyDesiredState(
                    desiredSignature = desiredSignature,
                    desiredProfiles = allowedProfiles,
                    connectionInput = connectionInput,
                    serverCaPem = serverCaPem,
                    clientIdentityJson = clientIdentityJson,
                )

                if (allowedProfiles.isEmpty()) {
                    clearRetryState(resetAttempts = true)
                    publishConnectionStatus(
                        state = FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_NETWORK,
                        message = waitingSummary ?: "No enabled sync profile is allowed on the current network",
                        retryCount = 0L,
                        nextRetryAt = null,
                    )
                    updateNotification(
                        "Waiting for allowed network",
                        waitingSummary ?: "No enabled sync profile is allowed on the current network",
                    )
                } else {
                    publishConnectionStatus(
                        state = connectionAttemptState(),
                        message = connectionAttemptMessage("service start", allowedProfiles.size),
                        retryCount = 0L,
                        nextRetryAt = nextRetryUnixMs,
                    )
                }

                true
            }
        }
    }

    private fun startStatusLoop() {
        if (statusJob?.isActive == true) {
            return
        }

        statusJob = scope.launch {
            while (isActive) {
                val status = withContext(Dispatchers.IO) {
                    runCatching { repository.getContinuousFolderSyncStatus() }.getOrNull()
                }
                val diagnosticsSummary = connectionDiagnosticsSummary(status)
                val activeProfileCount = status?.activeProfileCount ?: 0L
                val waitingMessage = waitingSummary
                val currentWaitingState = waitingState
                when {
                    !waitingMessage.isNullOrBlank() && activeProfileCount == 0L -> {
                        clearRetryState(resetAttempts = true)
                        publishConnectionStatus(
                            state = currentWaitingState ?: FOLDER_SYNC_CONNECTION_STATE_WAITING_FOR_NETWORK,
                            message = waitingMessage,
                            retryCount = 0L,
                            nextRetryAt = null,
                            lastSuccessfulConnectionUnixMs = diagnosticsSummary.lastSuccessfulConnectionUnixMs,
                            lastSuccessfulConnectionUrl = diagnosticsSummary.lastSuccessfulConnectionUrl,
                            failedAttempts = diagnosticsSummary.failedAttempts,
                        )
                    }
                    (status?.errorProfileCount ?: 0L) > 0L -> {
                        scheduleRetry(currentErrorMessage(status), diagnosticsSummary)
                    }
                    activeProfileCount > 0L -> {
                        hasEstablishedConnection = true
                        clearRetryState(resetAttempts = true)
                        val connectionState =
                            if (
                                (status?.startingProfileCount ?: 0L) > 0L ||
                                (status?.serviceState == "syncing" && status.lastSuccessUnixMs == null)
                            ) {
                                connectionAttemptState()
                            } else {
                                FOLDER_SYNC_CONNECTION_STATE_CONNECTED
                            }
                        val connectionMessage = status?.currentActivity
                            ?.takeIf { it.isNotBlank() }
                            ?: status?.serviceMessage
                            ?: "Continuous sync is active"
                        publishConnectionStatus(
                            state = connectionState,
                            message = connectionMessage,
                            retryCount = 0L,
                            nextRetryAt = null,
                            lastSuccessfulConnectionUnixMs = diagnosticsSummary.lastSuccessfulConnectionUnixMs,
                            lastSuccessfulConnectionUrl = diagnosticsSummary.lastSuccessfulConnectionUrl,
                            failedAttempts = diagnosticsSummary.failedAttempts,
                        )
                    }
                    else -> {
                        clearRetryState(resetAttempts = true)
                        publishConnectionStatus(
                            state = FOLDER_SYNC_CONNECTION_STATE_STOPPED,
                            message = status?.serviceMessage ?: "Continuous sync is stopped",
                            retryCount = 0L,
                            nextRetryAt = null,
                            lastSuccessfulConnectionUnixMs = diagnosticsSummary.lastSuccessfulConnectionUnixMs,
                            lastSuccessfulConnectionUrl = diagnosticsSummary.lastSuccessfulConnectionUrl,
                            failedAttempts = diagnosticsSummary.failedAttempts,
                        )
                    }
                }
                val (title, detail) = if (!waitingMessage.isNullOrBlank() && activeProfileCount == 0L) {
                    "Waiting for allowed network" to waitingMessage
                } else {
                    val contentText = status?.serviceMessage ?: "Continuous sync is starting"
                    val notificationTitle = when (status?.serviceState) {
                        "error" -> "Ironmesh sync issue"
                        "syncing" -> "Ironmesh syncing ${status.syncingProfileCount}/${status.activeProfileCount}"
                        "running" -> "Ironmesh sync active"
                        else -> "Ironmesh sync idle"
                    }
                    val notificationDetail = status?.currentActivity
                        ?.takeIf { it.isNotBlank() }
                        ?: status?.activeSummary
                            ?.takeIf { it.isNotBlank() }
                        ?: contentText
                    notificationTitle to notificationDetail
                }
                val logLine = status?.profiles
                    ?.takeIf { it.isNotEmpty() }
                    ?.joinToString(" | ") { profile ->
                        listOf(
                            profile.label,
                            profile.state,
                            profile.phase.takeIf { it.isNotBlank() },
                            profile.activity.takeIf { it.isNotBlank() },
                            profile.message.takeIf { it.isNotBlank() },
                        ).joinToString(":")
                    }
                    ?: detail
                if (logLine != lastLoggedStatusLine) {
                    Log.i(TAG, "continuous sync status: $logLine")
                    lastLoggedStatusLine = logLine
                }
                updateNotification(title, detail)
                delay(1_000)
            }
        }
    }

    private fun stopContinuousSyncAndSelf() {
        scope.launch(Dispatchers.IO) {
            repository.stopAllContinuousFolderSync()
            waitingSummary = null
            waitingState = null
            lastDesiredSignature = null
            clearRetryState(
                resetAttempts = true,
                resetEstablishedConnection = true,
            )
            publishConnectionStatus(
                state = FOLDER_SYNC_CONNECTION_STATE_STOPPED,
                message = "Continuous sync is stopped",
                retryCount = 0L,
                nextRetryAt = null,
            )
            withContext(Dispatchers.Main) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private suspend fun applyDesiredState(
        desiredSignature: String,
        desiredProfiles: List<io.ironmesh.android.data.FolderSyncConfig>,
        connectionInput: String,
        serverCaPem: String?,
        clientIdentityJson: String?,
    ) {
        if (desiredSignature == lastDesiredSignature) {
            return
        }

        repository.stopAllContinuousFolderSync()

        for (profile in desiredProfiles) {
            val localFolder = File(profile.localFolder)
            val storageDiagnostics = FolderSyncStorageDiagnosticsHelper.collect(
                contentResolver = applicationContext.contentResolver,
                localFolder = profile.localFolder,
                explicitTreeUri = profile.localFolderTreeUri,
            )
            Log.i(
                TAG,
                "starting continuous sync profile=${profile.id} label=${profile.label} prefix=${profile.prefix.ifBlank { "<root>" }} localFolder=${profile.localFolder} exists=${localFolder.exists()} isDirectory=${localFolder.isDirectory} canRead=${localFolder.canRead()} rawSampleChildren=${storageDiagnostics.rawSampleChildren} treeUriSource=${storageDiagnostics.treeUriSource} treeUri=${storageDiagnostics.treeUri ?: "<none>"} safSampleChildren=${storageDiagnostics.safSampleChildren}",
            )
            repository.startContinuousFolderSync(
                profileId = profile.id,
                label = profile.label,
                connectionInput = connectionInput,
                localFolder = profile.localFolder,
                localFolderTreeUri = profile.localFolderTreeUri,
                prefix = profile.prefix.ifBlank { null },
                depth = profile.depth,
                serverCaPem = serverCaPem,
                clientIdentityJson = clientIdentityJson,
            )
        }

        lastDesiredSignature = desiredSignature
    }

    private fun requestReconcile(reason: String) {
        if (!reason.startsWith("retry attempt")) {
            retryJob?.cancel()
            retryJob = null
            nextRetryUnixMs = null
        }
        scope.launch {
            val started = runCatching {
                Log.i(TAG, "reconciling continuous sync: $reason")
                reconcileProfiles()
            }.getOrElse { error ->
                val retryReason = error.message ?: "Failed to start sync"
                scheduleRetry(retryReason)
                updateNotification("Ironmesh sync issue", retryReason)
                false
            }
            if (started) {
                startStatusLoop()
            }
        }
    }

    private fun registerNetworkCallback() {
        if (networkCallbackRegistered) {
            return
        }
        val connectivityManager = getSystemService(ConnectivityManager::class.java) ?: return
        runCatching {
            connectivityManager.registerDefaultNetworkCallback(networkCallback)
            networkCallbackRegistered = true
        }.onFailure { error ->
            Log.w(TAG, "failed to register network callback: ${error.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        if (!networkCallbackRegistered) {
            return
        }
        val connectivityManager = getSystemService(ConnectivityManager::class.java) ?: return
        runCatching {
            connectivityManager.unregisterNetworkCallback(networkCallback)
        }
        networkCallbackRegistered = false
    }

    private fun buildDesiredSignature(
        connectionInput: String,
        serverCaPem: String?,
        clientIdentityJson: String?,
        profiles: List<io.ironmesh.android.data.FolderSyncConfig>,
    ): String {
        return buildString {
            append(connectionInput.trim())
            append('|')
            append(serverCaPem.orEmpty())
            append('|')
            append(clientIdentityJson.orEmpty())
            profiles
                .sortedBy { profile -> profile.id }
                .forEach { profile ->
                    append('|')
                    append(profile.id)
                    append(':')
                    append(profile.hashCode())
                }
        }
    }

    private fun buildWaitingSummary(
        blockedProfileCount: Int,
        profileLabel: String,
        reason: String,
    ): String {
        return if (blockedProfileCount <= 1) {
            "$profileLabel is waiting: $reason"
        } else {
            "$blockedProfileCount sync profiles are waiting. First block: $profileLabel: $reason"
        }
    }

    private fun updateNotification(title: String, text: String) {
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, buildNotification(title, text))
    }

    private fun buildNotification(title: String, text: String) =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val notificationManager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Ironmesh Sync",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Continuous folder synchronization"
        }
        notificationManager.createNotificationChannel(channel)
    }

    companion object {
        private const val TAG = "FolderSyncService"
        private const val CHANNEL_ID = "ironmesh-folder-sync"
        private const val NOTIFICATION_ID = 4001
        private const val ACTION_REFRESH = "io.ironmesh.android.action.FOLDER_SYNC_REFRESH"
        private const val ACTION_RETRY = "io.ironmesh.android.action.FOLDER_SYNC_RETRY"
        private const val ACTION_STOP = "io.ironmesh.android.action.FOLDER_SYNC_STOP"

        fun syncConfigChanged(context: Context) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, FolderSyncForegroundService::class.java).apply {
                    action = ACTION_REFRESH
                },
            )
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, FolderSyncForegroundService::class.java))
        }

        fun retryNow(context: Context) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, FolderSyncForegroundService::class.java).apply {
                    action = ACTION_RETRY
                },
            )
        }
    }
}
