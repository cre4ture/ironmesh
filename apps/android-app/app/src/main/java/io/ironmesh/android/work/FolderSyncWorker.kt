package io.ironmesh.android.work

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import io.ironmesh.android.data.FolderSyncConfig
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import io.ironmesh.android.data.RustPreferencesBridge
import io.ironmesh.android.data.RustSafBridge
import io.ironmesh.android.data.FolderSyncStorageDiagnosticsHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class FolderSyncWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    private val repository = IronmeshRepository()

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        RustSafBridge.initialize(applicationContext)
        RustPreferencesBridge.initialize(applicationContext)
        if (repository.hasContinuousFolderSyncActive()) {
            Log.i(TAG, "continuous folder sync is active; skipping one-shot worker run")
            return@withContext Result.success()
        }

        val deviceAuth = IronmeshPreferences.getDeviceAuthState(applicationContext)
        val connectionInput = deviceAuth.preferredConnectionInput()
        val clientIdentityJson = deviceAuth.toClientIdentityJson()
        val serverCaPem = deviceAuth.serverCaPem.takeIf { !it.isNullOrBlank() }
        val profiles = IronmeshPreferences
            .getFolderSyncConfigs(applicationContext)
            .filter { it.enabled }

        if (profiles.isEmpty()) {
            return@withContext Result.success()
        }

        val failures = mutableListOf<String>()

        for (profile in profiles) {
            runCatching {
                syncProfile(connectionInput, serverCaPem, clientIdentityJson, profile)
            }.onFailure { error ->
                failures += "${profile.label}: ${error.message ?: "unknown"}"
                Log.e(TAG, "folder sync failed for profile=${profile.id}", error)
            }
        }

        if (failures.isEmpty()) {
            Result.success()
        } else {
            Result.retry()
        }
    }

    private suspend fun syncProfile(
        connectionInput: String,
        serverCaPem: String?,
        clientIdentityJson: String?,
        profile: FolderSyncConfig,
    ) {
        val localFolder = File(profile.localFolder)
        val storageDiagnostics = FolderSyncStorageDiagnosticsHelper.collect(
            contentResolver = applicationContext.contentResolver,
            localFolder = profile.localFolder,
            explicitTreeUri = profile.localFolderTreeUri,
        )
        Log.i(
            TAG,
            "running one-shot sync profile=${profile.id} prefix=${profile.prefix.ifBlank { "<root>" }} localFolder=${profile.localFolder} exists=${localFolder.exists()} isDirectory=${localFolder.isDirectory} canRead=${localFolder.canRead()} rawSampleChildren=${storageDiagnostics.rawSampleChildren} treeUriSource=${storageDiagnostics.treeUriSource} treeUri=${storageDiagnostics.treeUri ?: "<none>"} safSampleChildren=${storageDiagnostics.safSampleChildren}",
        )
        File(profile.localFolder).mkdirs()
        repository.runFolderSyncOnce(
            connectionInput = connectionInput,
            localFolder = profile.localFolder,
            localFolderTreeUri = profile.localFolderTreeUri,
            prefix = profile.prefix.ifBlank { null },
            depth = profile.depth,
            serverCaPem = serverCaPem,
            clientIdentityJson = clientIdentityJson,
        )

        Log.i(TAG, "synced profile=${profile.id} via rust runtime")
    }

    private companion object {
        private const val TAG = "FolderSyncWorker"
    }
}
