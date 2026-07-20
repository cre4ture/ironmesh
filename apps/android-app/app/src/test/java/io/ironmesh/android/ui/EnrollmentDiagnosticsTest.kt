package io.ironmesh.android.ui

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
}
