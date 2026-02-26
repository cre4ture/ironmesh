package io.ironmesh.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import io.ironmesh.android.ui.MainViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val vm: MainViewModel = viewModel()
                    val state by vm.uiState

                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Text("Ironmesh Android MVP", style = MaterialTheme.typography.headlineSmall)

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = state.baseUrl,
                            onValueChange = vm::updateBaseUrl,
                            label = { Text("Server URL") },
                            singleLine = true,
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = state.key,
                            onValueChange = vm::updateKey,
                            label = { Text("Key") },
                            singleLine = true,
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = state.payload,
                            onValueChange = vm::updatePayload,
                            label = { Text("Payload") },
                        )

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = vm::checkHealth) { Text("Health") }
                            Button(onClick = vm::loadReplicationPlan) { Text("Plan") }
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = vm::putObject) { Text("PUT") }
                            Button(onClick = vm::getObject) { Text("GET") }
                        }

                        if (state.loading) {
                            CircularProgressIndicator()
                        }

                        Text("Status: ${state.status}")
                        if (state.replicationSummary.isNotBlank()) {
                            Text("Replication: ${state.replicationSummary}")
                        }
                        if (state.objectBody.isNotBlank()) {
                            Text("Object body:\n${state.objectBody}")
                        }
                    }
                }
            }
        }
    }
}
