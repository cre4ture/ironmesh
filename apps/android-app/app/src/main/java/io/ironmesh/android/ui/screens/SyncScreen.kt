@file:OptIn(
    androidx.compose.foundation.layout.ExperimentalLayoutApi::class,
    androidx.compose.material3.ExperimentalMaterial3Api::class,
)

package io.ironmesh.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.ironmesh.android.R
import io.ironmesh.android.data.FolderSyncConfig
import io.ironmesh.android.data.FolderSyncModificationRecord
import io.ironmesh.android.data.FolderSyncNetworkPolicy
import io.ironmesh.android.data.isConnected
import io.ironmesh.android.ui.FolderSyncActivityFilter
import io.ironmesh.android.ui.FolderSyncHistoryState
import io.ironmesh.android.ui.MainUiState
import io.ironmesh.android.ui.MainViewModel
import io.ironmesh.android.ui.components.EmptyStateCard
import io.ironmesh.android.ui.components.HeroTone
import io.ironmesh.android.ui.components.SectionCard
import io.ironmesh.android.ui.components.StatusHeroCard

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SyncScreen(
    state: MainUiState,
    vm: MainViewModel,
    onPickLocalFolder: () -> Unit,
    onEnsureWifiNameAccess: (FolderSyncNetworkPolicy) -> Unit,
) {
    val profileStatuses = state.folderSyncStatus.profiles.associateBy { it.profileId }
    val connectionStatus = state.folderSyncConnectionStatus
    val hasProfiles = state.syncProfiles.isNotEmpty()
    var showCreateSheet by rememberSaveable { mutableStateOf(false) }
    var detailProfileId by rememberSaveable { mutableStateOf<String?>(null) }
    var editingProfileId by rememberSaveable { mutableStateOf<String?>(null) }
    val detailProfile = state.syncProfiles.firstOrNull { it.id == detailProfileId }
    val editingProfile = state.syncProfiles.firstOrNull { it.id == editingProfileId }
    val heroTone = when {
        state.folderSyncStatus.errorProfileCount > 0L -> HeroTone.Error
        !connectionStatus.isConnected() -> HeroTone.Warning
        else -> HeroTone.Good
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        StatusHeroCard(
            title = folderSyncConnectionHeadline(connectionStatus, state.folderSyncStatus, hasProfiles),
            subtitle = folderSyncConnectionSummary(connectionStatus, state.folderSyncStatus),
            tone = heroTone,
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(onClick = { showCreateSheet = true }) {
                    Text(stringResource(R.string.new_profile))
                }
                if (shouldShowRetryConnectionAction(connectionStatus, hasProfiles)) {
                    OutlinedButton(onClick = vm::retryFolderSyncConnection) {
                        Text(stringResource(R.string.retry_connection))
                    }
                }
                OutlinedButton(onClick = vm::runFolderSyncNow) {
                    Text(stringResource(R.string.sync_now))
                }
            }
        }

        SectionCard(title = stringResource(R.string.connection_status)) {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SyncBadge(displayStatusToken(connectionStatus.state))
                if (connectionStatus.retryAttemptCount > 0L) {
                    SyncBadge("Retry ${connectionStatus.retryAttemptCount}")
                }
                connectionStatus.nextRetryUnixMs?.let { retryAt ->
                    SyncBadge("Next retry ${formatTimestamp(retryAt)}")
                }
            }
            Text(
                text = connectionStatus.message,
                style = MaterialTheme.typography.bodyMedium,
            )
            state.folderSyncStatus.currentActivity
                .takeIf { it.isNotBlank() && it != connectionStatus.message }
                ?.let { activity ->
                    Text(
                        text = activity,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
        }

        SectionCard(title = stringResource(R.string.sync_overview)) {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SyncBadge("Configured ${state.syncProfiles.size}")
                SyncBadge("Active ${state.folderSyncStatus.activeProfileCount}")
                if (state.folderSyncStatus.syncingProfileCount > 0L) {
                    SyncBadge("Syncing ${state.folderSyncStatus.syncingProfileCount}")
                }
                if (state.folderSyncStatus.errorProfileCount > 0L) {
                    SyncBadge("Errors ${state.folderSyncStatus.errorProfileCount}")
                }
                state.folderSyncStatus.lastSuccessUnixMs?.let { lastSuccess ->
                    SyncBadge("Last success ${formatTimestamp(lastSuccess)}")
                }
            }
        }

        if (state.syncProfiles.isEmpty()) {
            EmptyStateCard(
                title = stringResource(R.string.sync_empty_title),
                body = stringResource(R.string.sync_empty_body),
                actionLabel = stringResource(R.string.open_profile_creator),
                onAction = { showCreateSheet = true },
            )
        } else {
            state.syncProfiles.forEach { profile ->
                val profileStatus = profileStatuses[profile.id]
                SectionCard(
                    title = profile.label,
                    supportingText = profile.localFolder,
                ) {
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        SyncBadge(if (profile.enabled) "Enabled" else "Paused")
                        SyncBadge(profile.prefix.ifBlank { "<root>" })
                        SyncBadge(folderSyncAllowedTransportLabel(profile.networkPolicy))
                        profileStatus?.phase
                            ?.takeIf { it.isNotBlank() }
                            ?.let { phase -> SyncBadge(displayStatusToken(phase)) }
                    }
                    Text(
                        text = profileStatus?.message ?: "Waiting for sync activity",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        text = "Network rules: ${folderSyncNetworkPolicySummary(profile.networkPolicy)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    profileStatus?.let { status ->
                        Text(
                            text = profileInventorySummary(status),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        recentWorkSummary(status.metrics)?.let { summary ->
                            Text(
                                text = "Recent: $summary",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(onClick = { detailProfileId = profile.id }) {
                            Text(stringResource(R.string.details))
                        }
                        OutlinedButton(onClick = { editingProfileId = profile.id }) {
                            Text(stringResource(R.string.edit))
                        }
                    }
                }
            }
        }
    }

    if (showCreateSheet) {
        ModalBottomSheet(onDismissRequest = { showCreateSheet = false }) {
            NewSyncProfileSheet(
                state = state,
                vm = vm,
                onDismiss = { showCreateSheet = false },
                onPickLocalFolder = onPickLocalFolder,
                onEnsureWifiNameAccess = onEnsureWifiNameAccess,
            )
        }
    }

    if (detailProfile != null) {
        ModalBottomSheet(onDismissRequest = { detailProfileId = null }) {
            ProfileDetailSheet(
                profile = detailProfile,
                historyState = state.folderSyncHistory[detailProfile.id] ?: FolderSyncHistoryState(),
                vm = vm,
                onDismiss = { detailProfileId = null },
                onEditRules = {
                    detailProfileId = null
                    editingProfileId = detailProfile.id
                },
            )
        }
    }

    if (editingProfile != null) {
        ModalBottomSheet(onDismissRequest = { editingProfileId = null }) {
            NetworkPolicySheet(
                profile = editingProfile,
                vm = vm,
                onDismiss = { editingProfileId = null },
                onEnsureWifiNameAccess = onEnsureWifiNameAccess,
            )
        }
    }
}

@Composable
private fun NewSyncProfileSheet(
    state: MainUiState,
    vm: MainViewModel,
    onDismiss: () -> Unit,
    onPickLocalFolder: () -> Unit,
    onEnsureWifiNameAccess: (FolderSyncNetworkPolicy) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(stringResource(R.string.new_profile), style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = state.newSyncLabel,
            onValueChange = vm::updateNewSyncLabel,
            label = { Text(stringResource(R.string.profile_label)) },
            singleLine = true,
        )
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = state.newSyncPrefix,
            onValueChange = vm::updateNewSyncPrefix,
            label = { Text(stringResource(R.string.remote_prefix_optional)) },
            singleLine = true,
        )
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = state.newSyncLocalFolder,
            onValueChange = vm::updateNewSyncLocalFolder,
            label = { Text(stringResource(R.string.local_folder_path)) },
            singleLine = true,
        )
        OutlinedButton(onClick = onPickLocalFolder) {
            Text(stringResource(R.string.pick_folder))
        }
        Text(stringResource(R.string.network_rules), style = MaterialTheme.typography.titleMedium)
        NetworkPolicyEditor(
            allowWifi = state.newSyncAllowWifi,
            onAllowWifiChange = vm::updateNewSyncAllowWifi,
            allowCellular = state.newSyncAllowCellular,
            onAllowCellularChange = vm::updateNewSyncAllowCellular,
            allowOtherConnections = state.newSyncAllowOtherConnections,
            onAllowOtherConnectionsChange = vm::updateNewSyncAllowOtherConnections,
            allowRoaming = state.newSyncAllowRoaming,
            onAllowRoamingChange = vm::updateNewSyncAllowRoaming,
            allowedWifiSsids = state.newSyncAllowedWifiSsids,
            onAllowedWifiSsidsChange = vm::updateNewSyncAllowedWifiSsids,
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp, Alignment.End),
        ) {
            OutlinedButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
            Button(
                onClick = {
                    vm.addFolderSyncProfile()?.let { policy ->
                        onEnsureWifiNameAccess(policy)
                        onDismiss()
                    }
                },
            ) {
                Text(stringResource(R.string.save))
            }
        }
    }
}

@Composable
private fun ProfileDetailSheet(
    profile: FolderSyncConfig,
    historyState: FolderSyncHistoryState,
    vm: MainViewModel,
    onDismiss: () -> Unit,
    onEditRules: () -> Unit,
) {
    LaunchedEffect(profile.id) {
        if (!historyState.expanded && historyState.records.isEmpty() && !historyState.loading) {
            vm.toggleFolderSyncHistory(profile.id)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(profile.label, style = MaterialTheme.typography.titleLarge)
        Text(
            text = profile.localFolder,
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            text = "Scope ${profile.prefix.ifBlank { "<root>" }}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = {
                    vm.setFolderSyncProfileEnabled(profile.id, !profile.enabled)
                },
            ) {
                Text(if (profile.enabled) "Pause" else "Enable")
            }
            OutlinedButton(onClick = onEditRules) {
                Text(stringResource(R.string.network_rules))
            }
            OutlinedButton(
                onClick = {
                    vm.removeFolderSyncProfile(profile.id)
                    onDismiss()
                },
            ) {
                Text(stringResource(R.string.remove))
            }
        }
        Text(stringResource(R.string.recent_activity), style = MaterialTheme.typography.titleMedium)
        HistoryTimeline(
            historyState = historyState,
            onFilterSelected = { filter -> vm.setFolderSyncHistoryFilter(profile.id, filter) },
            onLoadMore = { vm.loadMoreFolderSyncHistory(profile.id) },
        )
    }
}

@Composable
private fun NetworkPolicySheet(
    profile: FolderSyncConfig,
    vm: MainViewModel,
    onDismiss: () -> Unit,
    onEnsureWifiNameAccess: (FolderSyncNetworkPolicy) -> Unit,
) {
    val initialPolicy = profile.networkPolicy.normalized()
    var allowWifi by rememberSaveable(profile.id) { mutableStateOf(initialPolicy.allowWifi) }
    var allowCellular by rememberSaveable(profile.id) { mutableStateOf(initialPolicy.allowCellular) }
    var allowOtherConnections by rememberSaveable(profile.id) {
        mutableStateOf(initialPolicy.allowOtherConnections)
    }
    var allowRoaming by rememberSaveable(profile.id) { mutableStateOf(initialPolicy.allowRoaming) }
    var allowedWifiSsids by rememberSaveable(profile.id) {
        mutableStateOf(initialPolicy.allowedWifiSsids.joinToString(", "))
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(stringResource(R.string.network_rules), style = MaterialTheme.typography.titleLarge)
        Text(profile.label, style = MaterialTheme.typography.bodyMedium)
        NetworkPolicyEditor(
            allowWifi = allowWifi,
            onAllowWifiChange = { allowWifi = it },
            allowCellular = allowCellular,
            onAllowCellularChange = { allowCellular = it },
            allowOtherConnections = allowOtherConnections,
            onAllowOtherConnectionsChange = { allowOtherConnections = it },
            allowRoaming = allowRoaming,
            onAllowRoamingChange = { allowRoaming = it },
            allowedWifiSsids = allowedWifiSsids,
            onAllowedWifiSsidsChange = { allowedWifiSsids = it },
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp, Alignment.End),
        ) {
            OutlinedButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
            Button(
                onClick = {
                    val updatedPolicy = FolderSyncNetworkPolicy(
                        allowWifi = allowWifi,
                        allowCellular = allowCellular,
                        allowOtherConnections = allowOtherConnections,
                        allowRoaming = allowRoaming,
                        allowedWifiSsids = io.ironmesh.android.data.parseAllowedWifiSsidsInput(
                            allowedWifiSsids,
                        ),
                    ).normalized()
                    if (vm.updateFolderSyncProfileNetworkPolicy(profile.id, updatedPolicy)) {
                        onEnsureWifiNameAccess(updatedPolicy)
                        onDismiss()
                    }
                },
            ) {
                Text(stringResource(R.string.save))
            }
        }
    }
}

@Composable
private fun NetworkPolicyEditor(
    allowWifi: Boolean,
    onAllowWifiChange: (Boolean) -> Unit,
    allowCellular: Boolean,
    onAllowCellularChange: (Boolean) -> Unit,
    allowOtherConnections: Boolean,
    onAllowOtherConnectionsChange: (Boolean) -> Unit,
    allowRoaming: Boolean,
    onAllowRoamingChange: (Boolean) -> Unit,
    allowedWifiSsids: String,
    onAllowedWifiSsidsChange: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        NetworkToggleRow(
            label = stringResource(R.string.wi_fi),
            detail = "Allow sync when the active connection is Wi-Fi.",
            checked = allowWifi,
            onCheckedChange = onAllowWifiChange,
        )
        NetworkToggleRow(
            label = stringResource(R.string.mobile_data),
            detail = "Allow sync over cellular data.",
            checked = allowCellular,
            onCheckedChange = onAllowCellularChange,
        )
        NetworkToggleRow(
            label = stringResource(R.string.roaming),
            detail = "Only applies when mobile data is enabled.",
            checked = allowRoaming,
            enabled = allowCellular,
            onCheckedChange = onAllowRoamingChange,
        )
        NetworkToggleRow(
            label = stringResource(R.string.other_connections),
            detail = "Allow Ethernet, VPN or other non-Wi-Fi/non-cellular connections.",
            checked = allowOtherConnections,
            onCheckedChange = onAllowOtherConnectionsChange,
        )
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = allowedWifiSsids,
            onValueChange = onAllowedWifiSsidsChange,
            enabled = allowWifi,
            label = { Text(stringResource(R.string.allowed_wifi_names_optional)) },
            placeholder = { Text(stringResource(R.string.wifi_placeholder)) },
        )
        Text(
            text = stringResource(R.string.wifi_help_text),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun NetworkToggleRow(
    label: String,
    detail: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean = true,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            enabled = enabled,
        )
    }
}

@Composable
private fun HistoryTimeline(
    historyState: FolderSyncHistoryState,
    onFilterSelected: (FolderSyncActivityFilter) -> Unit,
    onLoadMore: () -> Unit,
) {
    val filteredRecords = historyState.records.filter { record ->
        folderSyncHistoryMatchesFilter(record, historyState.filter)
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FolderSyncActivityFilter.entries.forEach { filter ->
                FilterChip(
                    selected = historyState.filter == filter,
                    onClick = { onFilterSelected(filter) },
                    label = { Text(folderSyncActivityFilterLabel(filter)) },
                )
            }
        }
        historyState.error?.takeIf { it.isNotBlank() }?.let { error ->
            Text(
                text = error,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        when {
            filteredRecords.isEmpty() && historyState.loading -> {
                Text(
                    text = "Loading activity...",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            filteredRecords.isEmpty() -> {
                Text(
                    text = "No recent activity yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            else -> {
                filteredRecords.forEach { record ->
                    TimelineRow(record)
                }
            }
        }
        if (historyState.nextBeforeId != null) {
            OutlinedButton(
                onClick = onLoadMore,
                enabled = !historyState.loading,
            ) {
                Text(stringResource(R.string.load_more))
            }
        }
    }
}

@Composable
private fun TimelineRow(record: FolderSyncModificationRecord) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = androidx.compose.foundation.shape.RoundedCornerShape(20.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                SyncBadge(folderSyncOperationLabel(record.operation))
                Text(
                    text = formatTimestamp(record.occurredUnixMs),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = record.localRelativePath.ifBlank { record.remoteKey },
                style = MaterialTheme.typography.bodyMedium,
            )
            folderSyncHistorySecondaryText(record)?.let { details ->
                Text(
                    text = details,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            record.errorText?.takeIf { it.isNotBlank() }?.let { message ->
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

@Composable
private fun SyncBadge(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = androidx.compose.foundation.shape.RoundedCornerShape(999.dp),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
        )
    }
}
