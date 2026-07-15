package io.ironmesh.android.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppConnectionStatusTest {
    @Test
    fun nextRetryDelayStartsAtTwoSeconds() {
        assertEquals(2_000L, nextAppConnectionRetryDelayMs(1))
    }

    @Test
    fun nextRetryDelayCapsAtSixtySeconds() {
        assertEquals(60_000L, nextAppConnectionRetryDelayMs(8))
    }

    @Test
    fun retryPendingReflectsScheduledRetryState() {
        val pending = AppConnectionStatus(
            state = APP_CONNECTION_STATE_RETRY_SCHEDULED,
            nextRetryUnixMs = 1234L,
        )
        val idle = AppConnectionStatus()

        assertTrue(pending.isRetryPending())
        assertFalse(idle.isRetryPending())
    }
}
