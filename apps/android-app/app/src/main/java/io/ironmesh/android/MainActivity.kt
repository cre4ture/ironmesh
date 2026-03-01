package io.ironmesh.android

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
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

                        Button(onClick = { openFilesAtIronmeshRoot(vm) }) {
                            Text("Open Files")
                        }

                        Button(onClick = { vm.openWebUi(::openWebUi) }) {
                            Text("Open Web UI")
                        }

                        Text(
                            "Folder Sync Profiles",
                            style = MaterialTheme.typography.titleMedium,
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = state.newSyncLabel,
                            onValueChange = vm::updateNewSyncLabel,
                            label = { Text("Profile Label") },
                            singleLine = true,
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = state.newSyncPrefix,
                            onValueChange = vm::updateNewSyncPrefix,
                            label = { Text("Remote Prefix (optional)") },
                            singleLine = true,
                        )

                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = state.newSyncLocalFolder,
                            onValueChange = vm::updateNewSyncLocalFolder,
                            label = { Text("Local Folder Path") },
                            singleLine = true,
                        )

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = vm::addFolderSyncProfile) {
                                Text("Add Sync Profile")
                            }
                            OutlinedButton(
                                onClick = {
                                    vm.updateNewSyncLocalFolder("/storage/emulated/0/DCIM/Camera")
                                },
                            ) {
                                Text("Use Camera Folder")
                            }
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = vm::runFolderSyncNow) { Text("Sync Now") }
                        }

                        if (state.syncProfiles.isEmpty()) {
                            Text("No sync profiles configured.")
                        }

                        state.syncProfiles.forEach { profile ->
                            Surface(modifier = Modifier.fillMaxWidth(), tonalElevation = 2.dp) {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    Text(profile.label, style = MaterialTheme.typography.titleSmall)
                                    Text(
                                        "Prefix: ${
                                            if (profile.prefix.isBlank()) "<root>" else profile.prefix
                                        }",
                                    )
                                    Text("Local: ${profile.localFolder}")
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Switch(
                                            checked = profile.enabled,
                                            onCheckedChange = { enabled ->
                                                vm.setFolderSyncProfileEnabled(profile.id, enabled)
                                            },
                                        )
                                        OutlinedButton(
                                            onClick = { vm.removeFolderSyncProfile(profile.id) },
                                        ) {
                                            Text("Remove")
                                        }
                                    }
                                }
                            }
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

    private fun openFilesAtIronmeshRoot(vm: MainViewModel) {
        val authority = "${packageName}.documents"
        val rootTreeUri = DocumentsContract.buildTreeDocumentUri(authority, "dir:")

        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PREFIX_URI_PERMISSION,
            )

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                putExtra(DocumentsContract.EXTRA_INITIAL_URI, rootTreeUri)
            }
        }

        val preferredPackages = listOf(
            "com.google.android.documentsui",
            "com.android.documentsui",
            "com.google.android.apps.nbu.files",
        )

        val launchIntent = preferredPackages
            .asSequence()
            .map { pkg -> Intent(intent).setPackage(pkg) }
            .firstOrNull { candidate ->
                candidate.resolveActivity(packageManager) != null
            } ?: intent

        try {
            startActivity(launchIntent)
            vm.setStatus("Opened Files picker at Ironmesh root")
        } catch (_: ActivityNotFoundException) {
            vm.setStatus("No compatible Files app found on this device")
        }
    }

    private fun openWebUi(url: String) {
        startActivity(WebUiActivity.intent(this, url))
    }
}
