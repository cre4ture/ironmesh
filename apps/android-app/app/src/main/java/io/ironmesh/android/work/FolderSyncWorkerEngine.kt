package io.ironmesh.android.work

import io.ironmesh.android.data.FolderSyncConfig

internal enum class FolderSyncWorkerOutcome {
    SUCCESS,
    RETRY,
}

internal fun interface FolderSyncWorkerRunGate {
    fun tryAcquire(owner: String): AutoCloseable?
}

internal object FolderSyncOneShotRunGate : FolderSyncWorkerRunGate {
    private val lock = Any()
    private var activeOwner: String? = null

    override fun tryAcquire(owner: String): AutoCloseable? {
        synchronized(lock) {
            if (activeOwner != null) {
                return null
            }
            activeOwner = owner
        }
        return AutoCloseable {
            synchronized(lock) {
                if (activeOwner == owner) {
                    activeOwner = null
                }
            }
        }
    }

    internal fun resetForTests() {
        synchronized(lock) {
            activeOwner = null
        }
    }
}

internal class FolderSyncWorkerEngine(
    private val runGate: FolderSyncWorkerRunGate = FolderSyncOneShotRunGate,
) {
    suspend fun run(
        continuousSyncActive: Boolean,
        eligibleProfiles: List<FolderSyncConfig>,
        syncProfile: suspend (FolderSyncConfig) -> Unit,
        onBusy: () -> Unit = {},
        onSkipped: () -> Unit = {},
        onProfileFailure: (FolderSyncConfig, Throwable) -> Unit = { _, _ -> },
    ): FolderSyncWorkerOutcome {
        if (continuousSyncActive) {
            onSkipped()
            return FolderSyncWorkerOutcome.SUCCESS
        }
        if (eligibleProfiles.isEmpty()) {
            return FolderSyncWorkerOutcome.SUCCESS
        }

        val lease = runGate.tryAcquire("one-shot-worker") ?: run {
            onBusy()
            return FolderSyncWorkerOutcome.RETRY
        }

        lease.use {
            var sawFailure = false
            for (profile in eligibleProfiles) {
                runCatching {
                    syncProfile(profile)
                }.onFailure { error ->
                    sawFailure = true
                    onProfileFailure(profile, error)
                }
            }
            return if (sawFailure) {
                FolderSyncWorkerOutcome.RETRY
            } else {
                FolderSyncWorkerOutcome.SUCCESS
            }
        }
    }
}
