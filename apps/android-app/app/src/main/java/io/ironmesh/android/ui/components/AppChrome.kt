package io.ironmesh.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.ironmesh.android.R
import io.ironmesh.android.ui.MainSection

@Composable
fun IronmeshAppShell(
    selectedSection: MainSection,
    onSelectSection: (MainSection) -> Unit,
    snackbarHostState: SnackbarHostState,
    deviceLabel: String?,
    content: @Composable (Modifier) -> Unit,
) {
    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        val useRail = maxWidth >= 720.dp
        if (useRail) {
            Row(modifier = Modifier.fillMaxSize()) {
                Surface(
                    modifier = Modifier.fillMaxHeight(),
                    color = MaterialTheme.colorScheme.surface,
                ) {
                    Column(
                        modifier = Modifier
                            .statusBarsPadding()
                            .padding(top = 8.dp),
                    ) {
                        NavigationRail(
                            containerColor = MaterialTheme.colorScheme.surface,
                        ) {
                            shellItems().forEach { item ->
                                NavigationRailItem(
                                    selected = selectedSection == item.section,
                                    onClick = { onSelectSection(item.section) },
                                    icon = {},
                                    label = { Text(stringResource(item.labelRes)) },
                                )
                            }
                        }
                    }
                }
                Scaffold(
                    modifier = Modifier.weight(1f),
                    topBar = {
                        IronmeshTopBar(
                            selectedSection = selectedSection,
                            deviceLabel = deviceLabel,
                        )
                    },
                    snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
                    contentWindowInsets = WindowInsets.navigationBars,
                ) { innerPadding ->
                    content(
                        Modifier
                            .fillMaxSize()
                            .padding(innerPadding)
                            .padding(horizontal = 20.dp, vertical = 16.dp),
                    )
                }
            }
        } else {
            Scaffold(
                topBar = {
                    IronmeshTopBar(
                        selectedSection = selectedSection,
                        deviceLabel = deviceLabel,
                    )
                },
                bottomBar = {
                    NavigationBar {
                        shellItems().forEach { item ->
                            NavigationBarItem(
                                selected = selectedSection == item.section,
                                onClick = { onSelectSection(item.section) },
                                icon = {},
                                label = { Text(stringResource(item.labelRes)) },
                            )
                        }
                    }
                },
                snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
                contentWindowInsets = WindowInsets.navigationBars,
            ) { innerPadding ->
                content(
                    Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun IronmeshTopBar(
    selectedSection: MainSection,
    deviceLabel: String?,
) {
    TopAppBar(
        title = {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(stringResource(titleForSection(selectedSection)))
                deviceLabel
                    ?.takeIf { it.isNotBlank() }
                    ?.let { label ->
                        Text(
                            text = label,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
            }
        },
    )
}

private data class ShellItem(
    val section: MainSection,
    val labelRes: Int,
)

private fun shellItems(): List<ShellItem> = listOf(
    ShellItem(MainSection.HOME, R.string.nav_home),
    ShellItem(MainSection.CONNECTIVITY, R.string.nav_connectivity),
    ShellItem(MainSection.SYNC, R.string.nav_sync),
    ShellItem(MainSection.LIBRARY, R.string.nav_library),
    ShellItem(MainSection.SETTINGS, R.string.nav_settings),
)

private fun titleForSection(section: MainSection): Int {
    return when (section) {
        MainSection.HOME -> R.string.nav_home
        MainSection.CONNECTIVITY -> R.string.nav_connectivity
        MainSection.SYNC -> R.string.nav_sync
        MainSection.LIBRARY -> R.string.nav_library
        MainSection.SETTINGS -> R.string.nav_settings
    }
}
