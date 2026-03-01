package io.ironmesh.android.work

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import io.ironmesh.android.data.IronmeshPreferences
import java.util.concurrent.TimeUnit

object FolderSyncScheduler {
    private const val UNIQUE_PERIODIC_WORK = "ironmesh-folder-sync-periodic"
    private const val UNIQUE_IMMEDIATE_WORK = "ironmesh-folder-sync-immediate"
    private const val PERIODIC_INTERVAL_MINUTES = 15L

    fun reschedule(context: Context) {
        val workManager = WorkManager.getInstance(context)
        val hasEnabledProfiles = IronmeshPreferences
            .getFolderSyncConfigs(context)
            .any { it.enabled }

        if (!hasEnabledProfiles) {
            workManager.cancelUniqueWork(UNIQUE_PERIODIC_WORK)
            return
        }

        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val request = PeriodicWorkRequestBuilder<FolderSyncWorker>(
            PERIODIC_INTERVAL_MINUTES,
            TimeUnit.MINUTES,
        )
            .setConstraints(constraints)
            .build()

        workManager.enqueueUniquePeriodicWork(
            UNIQUE_PERIODIC_WORK,
            ExistingPeriodicWorkPolicy.UPDATE,
            request,
        )
    }

    fun runNow(context: Context) {
        val hasEnabledProfiles = IronmeshPreferences
            .getFolderSyncConfigs(context)
            .any { it.enabled }
        if (!hasEnabledProfiles) {
            return
        }

        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val request = OneTimeWorkRequestBuilder<FolderSyncWorker>()
            .setConstraints(constraints)
            .build()

        WorkManager.getInstance(context).enqueueUniqueWork(
            UNIQUE_IMMEDIATE_WORK,
            ExistingWorkPolicy.REPLACE,
            request,
        )
    }
}
