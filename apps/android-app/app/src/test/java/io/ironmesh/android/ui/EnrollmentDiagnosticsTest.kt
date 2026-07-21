package io.ironmesh.android.ui

import io.ironmesh.android.data.ConnectionRouteAttemptSnapshot
import io.ironmesh.android.data.ConnectionRouteEndpointSnapshot
import io.ironmesh.android.data.ConnectionRouteSnapshot
import io.ironmesh.android.data.EnrollmentAccessVerification
import io.ironmesh.android.data.EnrollmentAccessVerificationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EnrollmentDiagnosticsTest {
    @Test
    fun newAttemptListsEveryEnrollmentStepAsPending() {
        val diagnostics = newEnrollmentDiagnostics()

        assertEquals(EnrollmentDiagnosticStepId.entries.toList(), diagnostics.map { it.id })
        assertEquals(
            List(EnrollmentDiagnosticStepId.entries.size) { EnrollmentDiagnosticStepStatus.PENDING },
            diagnostics.map { it.status },
        )
    }

    @Test
    fun failedStepKeepsTheExactErrorDetailAndLeavesOtherStepsUntouched() {
        val detail = "HTTP status client error (401 Unauthorized)"
        val diagnostics = newEnrollmentDiagnostics().withEnrollmentDiagnosticStatus(
            stepId = EnrollmentDiagnosticStepId.VERIFY_ACCESS,
            status = EnrollmentDiagnosticStepStatus.FAILED,
            detail = detail,
        )

        assertEquals(EnrollmentDiagnosticStepStatus.FAILED, diagnostics[1].status)
        assertEquals(detail, diagnostics[1].detail)
        assertEquals(EnrollmentDiagnosticStepStatus.PENDING, diagnostics[0].status)
        assertNull(diagnostics[0].detail)
        assertEquals(EnrollmentDiagnosticStepStatus.PENDING, diagnostics[2].status)
        assertNull(diagnostics[2].detail)
    }

    @Test
    fun emptyThrowableMessageFallsBackToItsClassName() {
        val detail = enrollmentDiagnosticErrorDetail(IllegalStateException())

        assertEquals(IllegalStateException::class.java.name, detail)
    }

    @Test
    fun throwableMessageIsPreservedExactlyForCopying() {
        val message = "  HTTP status client error (401 Unauthorized)  "
        val detail = enrollmentDiagnosticErrorDetail(IllegalStateException(message))

        assertEquals(message, detail)
    }

    @Test
    fun progressDetailShowsElapsedTimeAndPreferredTransportRoute() {
        val detail = enrollmentVerificationProgressDetail(
            elapsedMs = 65_000L,
            connectionRoutes = connectionRoutes(),
        )

        assertEquals(
            "Signed access request in progress for 1m 5s via direct route https://node.example",
            detail,
        )
    }

    @Test
    fun successDetailShowsTheCompletedSignedAccessRequestDuration() {
        val detail = enrollmentVerificationSuccessDetail(
            EnrollmentAccessVerification(
                elapsedMs = 90_000L,
                connectionRoutes = connectionRoutes(
                    recentAttempts = listOf(
                        ConnectionRouteAttemptSnapshot(
                            startedUnixMs = 1_000L,
                            finishedUnixMs = 74_000L,
                            method = "GET",
                            url = "https://node.example/api/v1/store/index?depth=1",
                            outcome = "success",
                        ),
                    ),
                ),
            ),
        )

        assertEquals(
            "Signed access verified in 1m 30s via direct route https://node.example " +
                "(request completed in 1m 13s)",
            detail,
        )
    }

    @Test
    fun verificationFailureUsesTheTransportErrorAndElapsedTime() {
        val error = EnrollmentAccessVerificationException(
            elapsedMs = 120_000L,
            connectionRoutes = connectionRoutes(lastError = "TLS handshake timed out"),
            cause = IllegalStateException("signed request failed"),
        )

        assertEquals(
            "Signed access verification failed after 2m via direct route https://node.example: " +
                "TLS handshake timed out",
            enrollmentDiagnosticErrorDetail(error),
        )
    }

    private fun connectionRoutes(
        lastError: String? = null,
        recentAttempts: List<ConnectionRouteAttemptSnapshot> = emptyList(),
    ): ConnectionRouteSnapshot {
        return ConnectionRouteSnapshot(
            generatedAtUnixMs = 1_000L,
            rankedIndices = listOf(0),
            endpoints = listOf(
                ConnectionRouteEndpointSnapshot(
                    index = 0,
                    pathKind = "direct",
                    locator = "https://node.example",
                    bootstrapRank = 0,
                    active = false,
                    score = 1.0,
                    consecutiveFailures = 0,
                    totalFailures = 0L,
                    totalSuccesses = 0L,
                    backgroundProbeInFlight = false,
                    lastError = lastError,
                    recentAttempts = recentAttempts,
                ),
            ),
        )
    }
}
