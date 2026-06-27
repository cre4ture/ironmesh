package io.ironmesh.servernode.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ServerNodeForegroundService.ensureRunning(this)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val vm: MainViewModel = viewModel()
                    val state by vm.uiState
                    MainScreen(
                        state = state,
                        onRefresh = vm::refresh,
                        onOpenNodeUi = { openNodeUi(state.status.localUrl.ifBlank { RustServerNodeBridge.localUiUrl() }) },
                    )
                }
            }
        }
    }

    private fun openNodeUi(url: String) {
        startActivity(WebUiActivity.intent(this, url))
    }
}

@Composable
private fun MainScreen(
    state: MainUiState,
    onRefresh: () -> Unit,
    onOpenNodeUi: () -> Unit,
) {
    val status = state.status
    val statusColor = when (status.state) {
        "running" -> Color(0xFF0D6B5C)
        "starting" -> Color(0xFFB45309)
        "error" -> Color(0xFFB42318)
        else -> Color(0xFF475467)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Image(
                painter = painterResource(R.drawable.ic_ironmesh_mark),
                contentDescription = "Ironmesh logo",
                modifier = Modifier.size(52.dp),
            )
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Ironmesh", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "Android Server Node",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(20.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = status.state.uppercase(),
                    color = statusColor,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                )
                Text(status.message, style = MaterialTheme.typography.bodyLarge)
                if (!status.lastError.isNullOrBlank()) {
                    SelectionContainer {
                        Text(
                            status.lastError,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(
                onClick = onOpenNodeUi,
                enabled = status.localUrl.isNotBlank(),
                modifier = Modifier.weight(1f),
            ) {
                Text("Open node UI")
            }
            OutlinedButton(
                onClick = onRefresh,
                modifier = Modifier.weight(1f),
            ) {
                Text("Refresh")
            }
        }

        DetailCard(
            title = "Local access",
            lines = listOf(
                "Embedded UI: ${status.localUrl.ifBlank { RustServerNodeBridge.localUiUrl() }}",
                "Listener: ${status.bindAddr.ifBlank { "${RustServerNodeBridge.DEFAULT_BIND_HOST}:${RustServerNodeBridge.DEFAULT_BIND_PORT}" }}",
                "Mode: ${status.mode ?: "starting"}",
                "Healthy: ${if (status.healthy) "yes" else "no"}",
                "Data dir: ${status.dataDir.ifBlank { "waiting for startup" }}",
            ),
        )

        DetailCard(
            title = "Bootstrap hint",
            lines = buildList {
                add("On first setup, use a LAN origin that other devices can reach.")
                if (state.candidateOrigins.isEmpty()) {
                    add("No active IPv4 LAN address detected yet.")
                } else {
                    add("Suggested origins:")
                    addAll(state.candidateOrigins)
                }
            },
        )

        DetailCard(
            title = "Notes",
            lines = listOf(
                "The app runs the Ironmesh managed bootstrap flow directly on Android.",
                "The foreground service keeps the local node alive while the app is backgrounded.",
                "The embedded WebView accepts the local node's self-signed certificate for the active host.",
            ),
        )

        Spacer(modifier = Modifier.height(8.dp))
    }
}

@Composable
private fun DetailCard(title: String, lines: List<String>) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(20.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    lines.forEach { line ->
                        Text(line, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
    }
}
