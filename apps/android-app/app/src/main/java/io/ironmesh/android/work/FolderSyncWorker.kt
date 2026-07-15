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
    private val engine = FolderSyncWorkerEngine()

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        RustSafBridge.initialize(applicationContext)
        RustPreferencesBridge.initialize(applicationContext)

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

        val networkDecisions = FolderSyncNetworkGate.evaluateProfiles(applicationContext, profiles)
        val eligibleProfiles = networkDecisions
            .filter { evaluation -> evaluation.decision.allowed }
            .map { evaluation -> evaluation.profile }
        val skippedProfiles = networkDecisions
            .filterNot { evaluation -> evaluation.decision.allowed }

        skippedProfiles.forEach { evaluation ->
            Log.i(
                TAG,
                "skipping one-shot sync profile=${evaluation.profile.id} reason=${evaluation.decision.reason}",
            )
        }

        if (eligibleProfiles.isEmpty()) {
            Log.i(TAG, "one-shot sync skipped because no enabled profile matches the current network policy")
            return@withContext Result.success()
        }

        val outcome = engine.run(
            continuousSyncActive = repository.hasContinuousFolderSyncActive(),
            eligibleProfiles = eligibleProfiles,
            syncProfile = { profile ->
                syncProfile(connectionInput, serverCaPem, clientIdentityJson, profile)
            },
            onBusy = {
                Log.i(TAG, "one-shot sync already active; retrying the worker later")
            },
            onSkipped = {
                Log.i(TAG, "continuous folder sync is active; skipping one-shot worker run")
            },
            onProfileFailure = { profile, error ->
                Log.e(TAG, "folder sync failed for profile=${profile.id}", error)
            },
        )

        when (outcome) {
            FolderSyncWorkerOutcome.SUCCESS -> Result.success()
            FolderSyncWorkerOutcome.RETRY -> Result.retry()
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
