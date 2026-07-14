package io.ironmesh.android.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FolderSyncConnectionStatusTest {
    @Test
    fun nextRetryDelayStartsAtTwoSeconds() {
        assertEquals(2_000L, nextFolderSyncRetryDelayMs(1))
    }

    @Test
    fun nextRetryDelayCapsAtSixtySeconds() {
        assertEquals(60_000L, nextFolderSyncRetryDelayMs(8))
    }

    @Test
    fun retryPendingReflectsScheduledRetryState() {
        val pending = FolderSyncConnectionStatus(
            state = FOLDER_SYNC_CONNECTION_STATE_RETRY_SCHEDULED,
            nextRetryUnixMs = 1234L,
        )
        val idle = FolderSyncConnectionStatus()

        assertTrue(pending.isRetryPending())
        assertFalse(idle.isRetryPending())
    }
}
