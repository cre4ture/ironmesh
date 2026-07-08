package io.ironmesh.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.ironmesh.android.BuildConfig
import io.ironmesh.android.R
import io.ironmesh.android.ui.MainUiState
import io.ironmesh.android.ui.components.PermissionExplainerCard
import io.ironmesh.android.ui.components.SectionCard

@Composable
fun SettingsScreen(
    state: MainUiState,
    hasPhotoAccess: Boolean,
    hasWifiNamePermissions: Boolean,
    isLocationEnabled: Boolean,
    onRequestPhotoAccess: () -> Unit,
    onRequestWifiNameAccess: () -> Unit,
    onOpenLocationSettings: () -> Unit,
    onOpenFiles: () -> Unit,
    onOpenWebConsole: () -> Unit,
    onClearEnrollment: () -> Unit,
    onKeyChange: (String) -> Unit,
    onPayloadChange: (String) -> Unit,
    onPutObject: () -> Unit,
    onGetObject: () -> Unit,
) {
    val wifiAccessGranted = hasWifiNamePermissions && isLocationEnabled
    val wifiStatusText = when {
        wifiAccessGranted -> stringResource(R.string.permission_granted)
        !hasWifiNamePermissions -> stringResource(R.string.permission_needed)
        else -> stringResource(R.string.location_required)
    }
    val wifiActionLabel = when {
        wifiAccessGranted -> null
        !hasWifiNamePermissions -> stringResource(R.string.grant_access)
        else -> stringResource(R.string.open_location_settings)
    }
    val wifiAction = when {
        wifiAccessGranted -> null
        !hasWifiNamePermissions -> onRequestWifiNameAccess
        else -> onOpenLocationSettings
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SectionCard(
            title = stringResource(R.string.settings_device),
            supportingText = state.deviceAuthState.deviceId.ifBlank { "This phone is not enrolled yet." },
        ) {
            Text(
                text = state.deviceAuthState.label.orEmpty().ifBlank { "No device label set" },
                style = MaterialTheme.typography.bodyLarge,
            )
            OutlinedButton(onClick = onClearEnrollment) {
                Text(stringResource(R.string.clear_device_identity))
            }
        }

        SectionCard(title = stringResource(R.string.settings_permissions)) {
            PermissionExplainerCard(
                title = stringResource(R.string.photo_access_title),
                body = stringResource(R.string.photo_access_body),
                status = stringResource(
                    if (hasPhotoAccess) {
                        R.string.permission_granted
                    } else {
                        R.string.permission_needed
                    },
                ),
                actionLabel = if (hasPhotoAccess) null else stringResource(R.string.grant_access),
                onAction = if (hasPhotoAccess) null else onRequestPhotoAccess,
            )
            PermissionExplainerCard(
                title = stringResource(R.string.wifi_access_title),
                body = stringResource(R.string.wifi_access_body),
                status = wifiStatusText,
                actionLabel = wifiActionLabel,
                onAction = wifiAction,
            )
        }

        SectionCard(title = stringResource(R.string.settings_storage)) {
            Button(onClick = onOpenFiles) {
                Text(stringResource(R.string.open_files))
            }
        }

        SectionCard(title = stringResource(R.string.settings_advanced)) {
            Button(onClick = onOpenWebConsole) {
                Text(stringResource(R.string.open_web_console))
            }
            OutlinedTextField(
                modifier = Modifier.fillMaxWidth(),
                value = state.key,
                onValueChange = onKeyChange,
                label = { Text(stringResource(R.string.key)) },
                singleLine = true,
            )
            OutlinedTextField(
                modifier = Modifier.fillMaxWidth(),
                value = state.payload,
                onValueChange = onPayloadChange,
                label = { Text(stringResource(R.string.payload)) },
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(onClick = onPutObject) {
                    Text(stringResource(R.string.put))
                }
                OutlinedButton(onClick = onGetObject) {
                    Text(stringResource(R.string.get))
                }
            }
        }

        SectionCard(title = stringResource(R.string.version)) {
            SelectionContainer {
                Text(BuildConfig.LONG_VERSION)
            }
        }
    }
}
