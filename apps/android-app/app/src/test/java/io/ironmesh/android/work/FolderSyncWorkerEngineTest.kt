package io.ironmesh.android.work

import io.ironmesh.android.data.FolderSyncConfig
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class FolderSyncWorkerEngineTest {
    @Before
    fun setUp() {
        FolderSyncOneShotRunGate.resetForTests()
    }

    @Test
    fun run_returnsRetry_whenAnotherWorkerAlreadyOwnsTheGate() = runBlocking {
        val lease = checkNotNull(FolderSyncOneShotRunGate.tryAcquire("existing-worker"))
        try {
            val engine = FolderSyncWorkerEngine()
            val syncedProfiles = mutableListOf<String>()

            val outcome = engine.run(
                continuousSyncActive = false,
                eligibleProfiles = listOf(profile("photos")),
                syncProfile = { profile -> syncedProfiles += profile.id },
            )

            assertEquals(FolderSyncWorkerOutcome.RETRY, outcome)
            assertEquals(emptyList<String>(), syncedProfiles)
        } finally {
            lease.close()
        }
    }

    @Test
    fun run_retriesWhenOneProfileFails_butContinuesRemainingProfiles() = runBlocking {
        val engine = FolderSyncWorkerEngine()
        val syncedProfiles = mutableListOf<String>()

        val outcome = engine.run(
            continuousSyncActive = false,
            eligibleProfiles = listOf(
                profile("photos"),
                profile("docs"),
                profile("media"),
            ),
            syncProfile = { profile ->
                syncedProfiles += profile.id
                if (profile.id == "docs") {
                    error("simulated failure")
                }
            },
        )

        assertEquals(FolderSyncWorkerOutcome.RETRY, outcome)
        assertEquals(listOf("photos", "docs", "media"), syncedProfiles)
    }

    @Test
    fun run_returnsSuccess_whenContinuousSyncIsAlreadyActive() = runBlocking {
        val engine = FolderSyncWorkerEngine()
        val syncedProfiles = mutableListOf<String>()

        val outcome = engine.run(
            continuousSyncActive = true,
            eligibleProfiles = listOf(profile("photos")),
            syncProfile = { profile -> syncedProfiles += profile.id },
        )

        assertEquals(FolderSyncWorkerOutcome.SUCCESS, outcome)
        assertEquals(emptyList<String>(), syncedProfiles)
    }

    @Test
    fun run_returnsSuccess_whenNoProfilesAreEligible() = runBlocking {
        val engine = FolderSyncWorkerEngine()
        val syncedProfiles = mutableListOf<String>()

        val outcome = engine.run(
            continuousSyncActive = false,
            eligibleProfiles = emptyList(),
            syncProfile = { profile -> syncedProfiles += profile.id },
        )

        assertEquals(FolderSyncWorkerOutcome.SUCCESS, outcome)
        assertEquals(emptyList<String>(), syncedProfiles)
    }

    private fun profile(id: String) = FolderSyncConfig(
        id = id,
        label = id.replaceFirstChar(Char::uppercaseChar),
        prefix = "",
        localFolder = "/tmp/$id",
    )
}
