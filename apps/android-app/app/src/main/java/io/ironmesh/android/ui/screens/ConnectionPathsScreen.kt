package io.ironmesh.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.ironmesh.android.R
import io.ironmesh.android.data.ConnectionRouteEndpointSnapshot
import io.ironmesh.android.data.ConnectionRouteSnapshot
import io.ironmesh.android.ui.MainUiState
import io.ironmesh.android.ui.components.HeroTone
import io.ironmesh.android.ui.components.MetricPill
import io.ironmesh.android.ui.components.SectionCard
import io.ironmesh.android.ui.components.StatusHeroCard

private data class ConnectionPathsSummary(
    val title: String,
    val detail: String,
    val tone: HeroTone,
)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ConnectionPathsScreen(
    state: MainUiState,
    onRefresh: () -> Unit,
) {
    val snapshot = state.connectionRoutes
    val snapshotUnixMs = snapshot?.generatedAtUnixMs
    val rankedEndpoints = rankedConnectionEndpoints(snapshot)
    val summary = buildConnectionPathsSummary(snapshot, state.connectionRoutesError)
    val activeEndpoint = snapshot?.endpoints?.firstOrNull { it.active } ?: rankedEndpoints.firstOrNull()
    val directCount = snapshot?.endpoints?.count(::isDirectPath) ?: 0
    val relayCount = snapshot?.endpoints?.count { it.pathKind == "relay_tunnel" } ?: 0
    val healthyCount = snapshot?.endpoints?.count {
        it.totalSuccesses > 0L && it.consecutiveFailures == 0 && !isCoolingDown(it, snapshotUnixMs)
    } ?: 0

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        StatusHeroCard(
            title = summary.title,
            subtitle = summary.detail,
            tone = summary.tone,
        ) {
            Button(onClick = onRefresh, enabled = !state.connectionRoutesLoading) {
                Text(
                    if (state.connectionRoutesLoading) {
                        stringResource(R.string.connection_paths_loading)
                    } else {
                        stringResource(R.string.connection_paths_refresh)
                    },
                )
            }
        }

        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            MetricPill(
                label = stringResource(R.string.connection_paths_metric_active),
                value = activeEndpoint?.let(::routeDisplayLabel) ?: "None",
            )
            MetricPill(
                label = stringResource(R.string.connection_paths_metric_direct),
                value = directCount.toString(),
            )
            MetricPill(
                label = stringResource(R.string.connection_paths_metric_relay),
                value = relayCount.toString(),
            )
            MetricPill(
                label = stringResource(R.string.connection_paths_metric_healthy),
                value = healthyCount.toString(),
            )
        }

        SectionCard(
            title = stringResource(R.string.connection_paths_methods_title),
            supportingText = stringResource(R.string.connection_paths_methods_body),
        ) {
            if (rankedEndpoints.isEmpty()) {
                Text(
                    text = stringResource(R.string.connection_paths_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    rankedEndpoints.forEachIndexed { index, endpoint ->
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = routeDisplayLabel(endpoint),
                                style = MaterialTheme.typography.titleSmall,
                            )
                            Text(
                                text = endpoint.locator,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                text = connectionMethodStateLine(endpoint, index, snapshotUnixMs),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp),
                            ) {
                                MetricPill(
                                    label = stringResource(R.string.connection_paths_metric_latency),
                                    value = endpoint.ewmaLatencyMs?.let(::formatLatency) ?: "n/a",
                                )
                                MetricPill(
                                    label = stringResource(R.string.connection_paths_metric_successes),
                                    value = endpoint.totalSuccesses.toString(),
                                )
                                MetricPill(
                                    label = stringResource(R.string.connection_paths_metric_failures),
                                    value = endpoint.totalFailures.toString(),
                                )
                            }
                            endpoint.lastSuccessUnixMs?.let { lastSuccess ->
                                Text(
                                    text = "Last success ${formatTimestamp(lastSuccess)}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            endpoint.lastError
                                ?.takeIf { it.isNotBlank() }
                                ?.let { error ->
                                    Text(
                                        text = error,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.error,
                                    )
                                }
                        }
                    }
                }
            }
        }

        SectionCard(
            title = stringResource(R.string.connection_paths_note_title),
            supportingText = stringResource(R.string.connection_paths_note_body),
        ) {
            Text(
                text = stringResource(R.string.connection_paths_note_detail),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

private fun buildConnectionPathsSummary(
    snapshot: ConnectionRouteSnapshot?,
    error: String?,
): ConnectionPathsSummary {
    if (!error.isNullOrBlank()) {
        return ConnectionPathsSummary(
            title = "Connection diagnostics failed",
            detail = error,
            tone = HeroTone.Error,
        )
    }
    if (snapshot == null || snapshot.endpoints.isEmpty()) {
        return ConnectionPathsSummary(
            title = "Loading connection paths",
            detail = "Gathering direct and relay route diagnostics from the cached client runtime.",
            tone = HeroTone.Neutral,
        )
    }

    val ranked = rankedConnectionEndpoints(snapshot)
    val active = snapshot.endpoints.firstOrNull { it.active } ?: ranked.firstOrNull()
    val hasSuccess = snapshot.endpoints.any { it.totalSuccesses > 0L }
    val hasProbeInFlight = snapshot.endpoints.any { it.backgroundProbeInFlight }
    val hasCooling = snapshot.endpoints.any { isCoolingDown(it, snapshot.generatedAtUnixMs) }

    if (!hasSuccess && snapshot.endpoints.all { it.totalFailures == 0L }) {
        return ConnectionPathsSummary(
            title = "Cold start",
            detail = "The router has not completed a measured request yet, so all path quality numbers are still warming up.",
            tone = HeroTone.Neutral,
        )
    }
    if (!hasSuccess && snapshot.endpoints.any { it.totalFailures > 0L }) {
        return ConnectionPathsSummary(
            title = "No healthy path",
            detail = "Every known route has failed recently. Inspect the method list below for cooldown windows and the latest transport errors.",
            tone = HeroTone.Error,
        )
    }
    if (active?.pathKind == "relay_tunnel" && active.consecutiveFailures == 0 && !hasProbeInFlight) {
        return ConnectionPathsSummary(
            title = "Relay fallback active",
            detail = "The client is currently reaching the cluster through rendezvous/relay. Direct paths may still be cooling down or simply rank behind relay right now.",
            tone = HeroTone.Warning,
        )
    }
    if (active != null && isDirectPath(active) && active.consecutiveFailures == 0 && !hasCooling && !hasProbeInFlight) {
        return ConnectionPathsSummary(
            title = "Direct path settled",
            detail = "A direct cluster path is active and the router is not re-evaluating alternatives right now.",
            tone = HeroTone.Good,
        )
    }
    return ConnectionPathsSummary(
        title = "Re-evaluating routes",
        detail = "The current path is usable, but the router is still reacting to recent failures or probing alternatives in the background.",
        tone = HeroTone.Warning,
    )
}

private fun rankedConnectionEndpoints(snapshot: ConnectionRouteSnapshot?): List<ConnectionRouteEndpointSnapshot> {
    if (snapshot == null) {
        return emptyList()
    }
    val byIndex = snapshot.endpoints.associateBy { it.index }
    val ranked = snapshot.rankedIndices.mapNotNull(byIndex::get)
    val missing = snapshot.endpoints.filter { endpoint -> endpoint.index !in snapshot.rankedIndices }
    return ranked + missing
}

private fun routeDisplayLabel(endpoint: ConnectionRouteEndpointSnapshot): String {
    val prefix = when (endpoint.pathKind) {
        "relay_tunnel" -> summarizeRelayLocator(endpoint.locator)?.let { "Relay via $it" } ?: "Relay"
        "direct_quic" -> "Direct QUIC"
        else -> "Direct HTTPS"
    }
    return endpoint.targetNodeId?.let { "$prefix to $it" } ?: prefix
}

private fun summarizeRelayLocator(locator: String): String? {
    val rendezvousIndex = locator.lastIndexOf("@")
    if (rendezvousIndex < 0 || rendezvousIndex + 1 >= locator.length) {
        return null
    }
    return summarizeUrl(locator.substring(rendezvousIndex + 1))
}

private fun summarizeUrl(value: String): String {
    return try {
        val uri = java.net.URI(value)
        val host = uri.host ?: value
        if (uri.port > 0) {
            "$host:${uri.port}"
        } else {
            host
        }
    } catch (_: Exception) {
        value
    }
}

private fun connectionMethodStateLine(
    endpoint: ConnectionRouteEndpointSnapshot,
    rankedIndex: Int,
    snapshotUnixMs: Long?,
): String {
    val states = mutableListOf<String>()
    if (endpoint.active) {
        states += "active"
    }
    if (rankedIndex == 0) {
        states += "top ranked"
    }
    if (endpoint.backgroundProbeInFlight) {
        states += "probing"
    }
    if (isCoolingDown(endpoint, snapshotUnixMs)) {
        states += "cooling down"
    }
    if (states.isEmpty()) {
        states += "standby"
    }
    return states.joinToString(" | ") { token -> displayStatusToken(token) }
}

private fun isDirectPath(endpoint: ConnectionRouteEndpointSnapshot): Boolean {
    return endpoint.pathKind == "direct_https" || endpoint.pathKind == "direct_quic"
}

private fun isCoolingDown(
    endpoint: ConnectionRouteEndpointSnapshot,
    snapshotUnixMs: Long?,
): Boolean {
    val until = endpoint.circuitOpenUntilUnixMs ?: return false
    return snapshotUnixMs != null && until > snapshotUnixMs
}

private fun formatLatency(value: Double): String {
    return String.format("%.1f ms", value)
}
