package io.ironmesh.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.ironmesh.android.BuildConfig
import io.ironmesh.android.R
import io.ironmesh.android.ui.MainUiState
import io.ironmesh.android.ui.components.PermissionExplainerCard
import io.ironmesh.android.ui.components.SectionCard
import io.ironmesh.android.ui.theme.DEFAULT_IRONMESH_ACCENT_COLOR_HEX
import io.ironmesh.android.ui.theme.IRONMESH_ACCENT_COLOR_SWATCHES
import io.ironmesh.android.ui.theme.ironmeshAccentColorToHex
import io.ironmesh.android.ui.theme.normalizeIronmeshAccentColorHex
import io.ironmesh.android.ui.theme.parseIronmeshAccentColorOrDefault
import kotlin.math.roundToInt

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
    onThemeAccentColorChange: (String) -> Unit,
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

        SectionCard(
            title = stringResource(R.string.settings_appearance),
            supportingText = stringResource(R.string.theme_color_body),
        ) {
            ThemeAccentColorEditor(
                accentColorHex = state.themeAccentColorHex,
                onAccentColorChange = onThemeAccentColorChange,
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

@Composable
private fun ThemeAccentColorEditor(
    accentColorHex: String,
    onAccentColorChange: (String) -> Unit,
) {
    val accentColor = parseIronmeshAccentColorOrDefault(accentColorHex)
    val red = colorChannel(accentColor.red)
    val green = colorChannel(accentColor.green)
    val blue = colorChannel(accentColor.blue)
    var hexInput by remember { mutableStateOf(accentColorHex) }

    LaunchedEffect(accentColorHex) {
        if (normalizeIronmeshAccentColorHex(hexInput) != accentColorHex) {
            hexInput = accentColorHex
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(accentColor)
                    .border(
                        width = 2.dp,
                        color = MaterialTheme.colorScheme.outline,
                        shape = CircleShape,
                    ),
            )
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = stringResource(R.string.theme_color_preview),
                    style = MaterialTheme.typography.labelLarge,
                )
                Text(
                    text = accentColorHex,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = hexInput,
            onValueChange = { value ->
                hexInput = value.uppercase()
                normalizeIronmeshAccentColorHex(value)?.let(onAccentColorChange)
            },
            label = { Text(stringResource(R.string.theme_color_hex_label)) },
            singleLine = true,
        )

        Text(
            text = stringResource(R.string.theme_color_presets),
            style = MaterialTheme.typography.labelLarge,
        )
        IRONMESH_ACCENT_COLOR_SWATCHES.chunked(3).forEach { rowColors ->
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                rowColors.forEach { swatch ->
                    ThemeAccentSwatch(
                        colorHex = swatch,
                        selected = swatch == accentColorHex,
                        onClick = { onAccentColorChange(swatch) },
                    )
                }
            }
        }

        ColorChannelSlider(
            label = stringResource(R.string.theme_color_red),
            value = red,
            onValueChange = { value ->
                onAccentColorChange(
                    updateAccentColorChannel(
                        accentColor = accentColor,
                        red = value,
                    ),
                )
            },
        )
        ColorChannelSlider(
            label = stringResource(R.string.theme_color_green),
            value = green,
            onValueChange = { value ->
                onAccentColorChange(
                    updateAccentColorChannel(
                        accentColor = accentColor,
                        green = value,
                    ),
                )
            },
        )
        ColorChannelSlider(
            label = stringResource(R.string.theme_color_blue),
            value = blue,
            onValueChange = { value ->
                onAccentColorChange(
                    updateAccentColorChannel(
                        accentColor = accentColor,
                        blue = value,
                    ),
                )
            },
        )

        OutlinedButton(onClick = { onAccentColorChange(DEFAULT_IRONMESH_ACCENT_COLOR_HEX) }) {
            Text(stringResource(R.string.theme_color_reset))
        }
    }
}

@Composable
private fun ThemeAccentSwatch(
    colorHex: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val swatchColor = parseIronmeshAccentColorOrDefault(colorHex)
    Box(
        modifier = Modifier
            .size(34.dp)
            .clip(CircleShape)
            .background(swatchColor)
            .border(
                width = if (selected) 3.dp else 1.dp,
                color = if (selected) {
                    MaterialTheme.colorScheme.onSurface
                } else {
                    MaterialTheme.colorScheme.outline
                },
                shape = CircleShape,
            )
            .clickable(onClick = onClick),
    )
}

@Composable
private fun ColorChannelSlider(
    label: String,
    value: Int,
    onValueChange: (Int) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(text = label, style = MaterialTheme.typography.labelLarge)
            Text(
                text = value.toString(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Slider(
            value = value.toFloat(),
            onValueChange = { next -> onValueChange(next.roundToInt().coerceIn(0, 255)) },
            valueRange = 0f..255f,
        )
    }
}

private fun updateAccentColorChannel(
    accentColor: Color,
    red: Int? = null,
    green: Int? = null,
    blue: Int? = null,
): String =
    ironmeshAccentColorToHex(
        accentColor.copy(
            red = (red ?: colorChannel(accentColor.red)) / 255f,
            green = (green ?: colorChannel(accentColor.green)) / 255f,
            blue = (blue ?: colorChannel(accentColor.blue)) / 255f,
        ),
    )

private fun colorChannel(value: Float): Int =
    (value.coerceIn(0f, 1f) * 255f).roundToInt().coerceIn(0, 255)
