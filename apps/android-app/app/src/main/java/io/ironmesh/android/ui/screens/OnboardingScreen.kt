package io.ironmesh.android.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.ironmesh.android.R
import io.ironmesh.android.ui.MainUiState
import io.ironmesh.android.ui.components.PermissionExplainerCard
import io.ironmesh.android.ui.components.SectionCard

@Composable
fun OnboardingScreen(
    state: MainUiState,
    onDeviceLabelChange: (String) -> Unit,
    onBootstrapInputChange: (String) -> Unit,
    onScanQr: () -> Unit,
    onEnroll: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SectionCard(
            title = stringResource(R.string.onboarding_title),
            supportingText = stringResource(R.string.onboarding_body),
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Image(
                    painter = painterResource(R.drawable.ic_ironmesh_mark),
                    contentDescription = null,
                )
                Text(
                    text = stringResource(R.string.required_access),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            OutlinedTextField(
                modifier = Modifier.fillMaxWidth(),
                value = state.deviceLabelInput,
                onValueChange = onDeviceLabelChange,
                label = { Text(stringResource(R.string.device_label)) },
                singleLine = true,
            )
            OutlinedTextField(
                modifier = Modifier.fillMaxWidth(),
                value = state.bootstrapInput,
                onValueChange = onBootstrapInputChange,
                label = { Text(stringResource(R.string.bootstrap_claim_or_bundle)) },
                minLines = 5,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    onClick = onEnroll,
                    enabled = !state.loading,
                ) {
                    if (state.loading) {
                        CircularProgressIndicator(
                            modifier = Modifier
                                .padding(end = 8.dp)
                                .size(16.dp),
                            strokeWidth = 2.dp,
                        )
                    }
                    Text(stringResource(R.string.enroll_device))
                }
                OutlinedButton(
                    onClick = onScanQr,
                    enabled = !state.loading,
                ) {
                    Text(stringResource(R.string.scan_qr))
                }
            }
        }

        PermissionExplainerCard(
            title = stringResource(R.string.folder_access_title),
            body = stringResource(R.string.folder_access_body),
            status = stringResource(R.string.permission_needed),
        )
        PermissionExplainerCard(
            title = stringResource(R.string.photo_access_title),
            body = stringResource(R.string.photo_access_body),
            status = stringResource(R.string.permission_needed),
        )
        PermissionExplainerCard(
            title = stringResource(R.string.wifi_access_title),
            body = stringResource(R.string.wifi_access_body),
            status = stringResource(R.string.permission_needed),
        )
    }
}
