package io.ironmesh.android.work

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.ironmesh.android.data.RustSafBridge
import io.ironmesh.android.data.FolderSyncStorageDiagnosticsHelper
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class FolderSyncForegroundService : Service() {

    private val repository = IronmeshRepository()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var statusJob: Job? = null
    private var lastLoggedStatusLine: String? = null

    override fun onCreate() {
        super.onCreate()
        RustSafBridge.initialize(applicationContext)
        ensureNotificationChannel()
        startForeground(
            NOTIFICATION_ID,
            buildNotification("Starting continuous sync", "Preparing folder sync runtime"),
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopContinuousSyncAndSelf()
                return START_NOT_STICKY
            }
            else -> {
                scope.launch {
                    val started = runCatching { reconcileProfiles() }
                        .getOrElse { error ->
                            updateNotification("Ironmesh sync issue", error.message ?: "Failed to start sync")
                            false
                        }
                    if (started) {
                        startStatusLoop()
                    }
                }
                return START_STICKY
            }
        }
    }

    override fun onDestroy() {
        statusJob?.cancel()
        repository.stopAllContinuousFolderSync()
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private suspend fun reconcileProfiles(): Boolean {
        return withContext(Dispatchers.IO) {
            val deviceAuth = IronmeshPreferences.getDeviceAuthState(applicationContext)
            val baseUrl = deviceAuth.serverBaseUrl.ifBlank {
                IronmeshPreferences.getBaseUrl(applicationContext)
            }
            val authToken = deviceAuth.deviceToken.takeIf { it.isNotBlank() }
            val serverCaPem = deviceAuth.serverCaPem.takeIf { !it.isNullOrBlank() }
            val profiles = IronmeshPreferences
                .getFolderSyncConfigs(applicationContext)
                .filter { it.enabled }

            repository.stopAllContinuousFolderSync()

            if (profiles.isEmpty()) {
                withContext(Dispatchers.Main) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
                return@withContext false
            }

            for (profile in profiles) {
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
                    baseUrl = baseUrl,
                    localFolder = profile.localFolder,
                    localFolderTreeUri = profile.localFolderTreeUri,
                    prefix = profile.prefix.ifBlank { null },
                    depth = profile.depth,
                    serverCaPem = serverCaPem,
                    authToken = authToken,
                )
            }
            true
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
                val contentText = status?.serviceMessage ?: "Continuous sync is starting"
                val title = when (status?.serviceState) {
                    "error" -> "Ironmesh sync issue"
                    "syncing" -> "Ironmesh syncing"
                    "running" -> "Ironmesh sync active"
                    else -> "Ironmesh sync idle"
                }
                val detail = status?.profiles
                    ?.takeIf { it.isNotEmpty() }
                    ?.joinToString(" | ") { profile -> "${profile.label}: ${profile.state}" }
                    ?: contentText
                val logLine = status?.profiles
                    ?.joinToString(" | ") { profile ->
                        "${profile.label}:${profile.state}:${profile.message}"
                    }
                    ?: contentText
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
            withContext(Dispatchers.Main) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
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
