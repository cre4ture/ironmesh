package io.ironmesh.android.ui

import io.ironmesh.android.data.ConnectionRouteAttemptSnapshot
import io.ironmesh.android.data.ConnectionRouteEndpointSnapshot
import io.ironmesh.android.data.ConnectionRouteSnapshot
import io.ironmesh.android.data.EnrollmentAccessVerification
import io.ironmesh.android.data.EnrollmentAccessVerificationException
import io.ironmesh.android.ui.screens.formatDurationMillis

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
    if (error is EnrollmentAccessVerificationException) {
        return enrollmentVerificationFailureDetail(error)
    }
    val message = error.message
    return if (message.isNullOrBlank()) error::class.java.name else message
}

fun enrollmentVerificationProgressDetail(
    elapsedMs: Long,
    connectionRoutes: ConnectionRouteSnapshot?,
): String {
    val route = enrollmentRouteDescription(connectionRoutes)
    return buildString {
        append("Signed access request in progress for ")
        append(formatDurationMillis(elapsedMs))
        route?.let {
            append(" via ")
            append(it)
        }
    }
}

fun enrollmentVerificationSuccessDetail(
    verification: EnrollmentAccessVerification,
): String {
    val route = enrollmentRouteDescription(verification.connectionRoutes)
    val storeIndexAttempt = enrollmentStoreIndexAttempt(verification.connectionRoutes)
    val requestDuration = storeIndexAttempt
        ?.finishedUnixMs
        ?.minus(storeIndexAttempt.startedUnixMs)
        ?.takeIf { it >= 0L }
    return buildString {
        append("Signed access verified in ")
        append(formatDurationMillis(verification.elapsedMs))
        route?.let {
            append(" via ")
            append(it)
        }
        requestDuration?.let {
            append(" (request completed in ")
            append(formatDurationMillis(it))
            append(')')
        }
    }
}

private fun enrollmentVerificationFailureDetail(
    error: EnrollmentAccessVerificationException,
): String {
    val causeDetail = error.cause?.message?.takeIf { it.isNotBlank() }
        ?: error.message.orEmpty()
    val route = enrollmentRouteDescription(error.connectionRoutes)
    val transportError = enrollmentRouteEndpoint(error.connectionRoutes)
        ?.lastError
        ?.takeIf { it.isNotBlank() }
    return buildString {
        append("Signed access verification failed after ")
        append(formatDurationMillis(error.elapsedMs))
        route?.let {
            append(" via ")
            append(it)
        }
        append(": ")
        append(transportError ?: causeDetail)
    }
}

private fun enrollmentRouteDescription(connectionRoutes: ConnectionRouteSnapshot?): String? {
    val endpoint = enrollmentRouteEndpoint(connectionRoutes) ?: return null
    return "${endpoint.pathKind} route ${endpoint.locator}"
}

private fun enrollmentRouteEndpoint(
    connectionRoutes: ConnectionRouteSnapshot?,
): ConnectionRouteEndpointSnapshot? {
    connectionRoutes ?: return null
    val rankedEndpoint = connectionRoutes.rankedIndices
        .asSequence()
        .mapNotNull { index -> connectionRoutes.endpoints.firstOrNull { it.index == index } }
        .firstOrNull()
    return connectionRoutes.endpoints.firstOrNull { it.active }
        ?: rankedEndpoint
        ?: connectionRoutes.endpoints.firstOrNull()
}

private fun enrollmentStoreIndexAttempt(
    connectionRoutes: ConnectionRouteSnapshot?,
): ConnectionRouteAttemptSnapshot? {
    return enrollmentRouteEndpoint(connectionRoutes)
        ?.recentAttempts
        ?.lastOrNull { attempt ->
            attempt.method.equals("GET", ignoreCase = true) &&
                attempt.url.contains("/api/v1/store/index")
        }
}
