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
import io.ironmesh.android.data.FolderSyncStorageDiagnosticsHelper
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import io.ironmesh.android.data.RustPreferencesBridge
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
            else -> {
                requestReconcile("service start")
                return START_STICKY
            }
        }
    }

    override fun onDestroy() {
        statusJob?.cancel()
        unregisterNetworkCallback()
        repository.stopAllContinuousFolderSync()
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

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
                    lastDesiredSignature = null
                    withContext(Dispatchers.Main) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                    return@withContext false
                }

                if (connectionInput.isBlank() || clientIdentityJson.isNullOrBlank()) {
                    applyDesiredState(
                        desiredSignature = "",
                        desiredProfiles = emptyList(),
                        connectionInput = connectionInput,
                        serverCaPem = serverCaPem,
                        clientIdentityJson = clientIdentityJson,
                    )
                    waitingSummary = "Enroll this device before continuous sync can run"
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
                    updateNotification(
                        "Waiting for allowed network",
                        waitingSummary ?: "No enabled sync profile is allowed on the current network",
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
                val activeProfileCount = status?.activeProfileCount ?: 0L
                val waitingMessage = waitingSummary
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
            lastDesiredSignature = null
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
        scope.launch {
            val started = runCatching {
                Log.i(TAG, "reconciling continuous sync: $reason")
                reconcileProfiles()
            }.getOrElse { error ->
                updateNotification("Ironmesh sync issue", error.message ?: "Failed to start sync")
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
    }
}
