package io.ironmesh.android

import android.content.ActivityNotFoundException
import android.content.ContentResolver
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Point
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
import android.util.Size
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import io.ironmesh.android.ui.GalleryImageItem
import io.ironmesh.android.ui.GallerySortOption
import io.ironmesh.android.ui.MainUiState
import io.ironmesh.android.ui.MainViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

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

                        ServerControls(
                            state = state,
                            vm = vm,
                            onOpenFiles = { openFilesAtIronmeshRoot(vm) },
                            onOpenWebUi = { vm.openWebUi(::openWebUi) },
                        )
                        FolderSyncControls(state = state, vm = vm)
                        GallerySection(state = state, vm = vm)

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

@Composable
private fun ServerControls(
    state: MainUiState,
    vm: MainViewModel,
    onOpenFiles: () -> Unit,
    onOpenWebUi: () -> Unit,
) {
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

    Button(onClick = onOpenFiles) {
        Text("Open Files")
    }

    Button(onClick = onOpenWebUi) {
        Text("Open Web UI")
    }
}

@Composable
private fun FolderSyncControls(
    state: MainUiState,
    vm: MainViewModel,
) {
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
        Surface(
            modifier = Modifier.fillMaxWidth(),
            tonalElevation = 2.dp,
            shape = RoundedCornerShape(18.dp),
        ) {
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
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun GallerySection(
    state: MainUiState,
    vm: MainViewModel,
) {
    Text("Gallery", style = MaterialTheme.typography.titleMedium)

    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Button(onClick = vm::refreshGallery) {
            Text("Refresh Gallery")
        }
        FilterChip(
            selected = state.gallerySort == GallerySortOption.CREATION_TIME,
            onClick = { vm.updateGallerySort(GallerySortOption.CREATION_TIME) },
            label = { Text("Creation Time") },
        )
        FilterChip(
            selected = state.gallerySort == GallerySortOption.NAME,
            onClick = { vm.updateGallerySort(GallerySortOption.NAME) },
            label = { Text("Name") },
        )
    }

    if (state.galleryLoading) {
        CircularProgressIndicator()
    } else if (state.galleryItems.isEmpty()) {
        Text("No images loaded from the document provider.")
    } else {
        GalleryGrid(items = state.galleryItems)
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun GalleryGrid(items: List<GalleryImageItem>) {
    BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
        val gap = 12.dp
        val columns = when {
            maxWidth < 420.dp -> 2
            maxWidth < 800.dp -> 3
            else -> 4
        }
        val cardWidth = (maxWidth - gap * (columns - 1)) / columns

        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            maxItemsInEachRow = columns,
            horizontalArrangement = Arrangement.spacedBy(gap),
            verticalArrangement = Arrangement.spacedBy(gap),
        ) {
            items.forEach { item ->
                GalleryCard(
                    item = item,
                    modifier = Modifier.width(cardWidth),
                )
            }
        }
    }
}

@Composable
private fun GalleryCard(
    item: GalleryImageItem,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        tonalElevation = 3.dp,
        shape = RoundedCornerShape(20.dp),
    ) {
        Column {
            ProviderThumbnail(
                documentUri = item.documentUri,
                contentDescription = item.displayName,
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(1f),
            )

            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = item.displayName,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = item.remotePath,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                galleryMetaText(item)?.let { meta ->
                    Text(
                        text = meta,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                item.createdAtUnixMs?.let { createdAt ->
                    Text(
                        text = "Created ${formatTimestamp(createdAt)}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}

@Composable
private fun ProviderThumbnail(
    documentUri: Uri,
    contentDescription: String,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val thumbnail by produceState<Bitmap?>(initialValue = null, documentUri) {
        value = withContext(Dispatchers.IO) {
            loadDocumentThumbnail(context.contentResolver, documentUri, 384)
        }
    }

    Box(
        modifier = modifier.background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        val bitmap = thumbnail
        if (bitmap != null) {
            Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = contentDescription,
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Text(
                text = "Preview unavailable",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(12.dp),
            )
        }
    }
}

private fun galleryMetaText(item: GalleryImageItem): String? {
    val parts = mutableListOf<String>()
    if (item.width != null && item.height != null) {
        parts += "${item.width} x ${item.height}"
    }
    if (!item.thumbnailStatus.isNullOrBlank()) {
        parts += item.thumbnailStatus
    }
    return parts.takeIf { it.isNotEmpty() }?.joinToString(" - ")
}

private fun formatTimestamp(value: Long): String {
    return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
        .withZone(ZoneId.systemDefault())
        .format(Instant.ofEpochMilli(value))
}

private fun loadDocumentThumbnail(
    contentResolver: ContentResolver,
    documentUri: Uri,
    sizePx: Int,
): Bitmap? {
    return runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            contentResolver.loadThumbnail(documentUri, Size(sizePx, sizePx), null)
        } else {
            DocumentsContract.getDocumentThumbnail(
                contentResolver,
                documentUri,
                Point(sizePx, sizePx),
                null,
            )
        }
    }.getOrNull()
}
