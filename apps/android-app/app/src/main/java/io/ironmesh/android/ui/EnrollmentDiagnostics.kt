package io.ironmesh.android.ui

enum class EnrollmentDiagnosticStepId {
    BOOTSTRAP,
    VERIFY_ACCESS,
    SAVE_IDENTITY,
}

enum class EnrollmentDiagnosticStepStatus {
    PENDING,
    IN_PROGRESS,
    SUCCEEDED,
    FAILED,
}

data class EnrollmentDiagnosticStep(
    val id: EnrollmentDiagnosticStepId,
    val status: EnrollmentDiagnosticStepStatus = EnrollmentDiagnosticStepStatus.PENDING,
    val detail: String? = null,
)

fun newEnrollmentDiagnostics(): List<EnrollmentDiagnosticStep> =
    EnrollmentDiagnosticStepId.entries.map(::EnrollmentDiagnosticStep)

fun List<EnrollmentDiagnosticStep>.withEnrollmentDiagnosticStatus(
    stepId: EnrollmentDiagnosticStepId,
    status: EnrollmentDiagnosticStepStatus,
    detail: String? = null,
): List<EnrollmentDiagnosticStep> = map { step ->
    if (step.id == stepId) {
        step.copy(status = status, detail = detail)
    } else {
        step
    }
}

fun enrollmentDiagnosticErrorDetail(error: Throwable): String {
    val message = error.message
    return if (message.isNullOrBlank()) error::class.java.name else message
}
