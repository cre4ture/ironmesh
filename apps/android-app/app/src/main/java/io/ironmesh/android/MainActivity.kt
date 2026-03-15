package io.ironmesh.android

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.ContentResolver
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Point
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
import android.util.Log
import android.util.Size
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.viewmodel.compose.viewModel
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import io.ironmesh.android.data.RustSafBridge
import io.ironmesh.android.ui.GalleryImageItem
import io.ironmesh.android.ui.GallerySortOption
import io.ironmesh.android.ui.MainSection
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
        RustSafBridge.initialize(applicationContext)
        enableEdgeToEdge()

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val vm: MainViewModel = viewModel()
                    val state by vm.uiState

                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Text("Ironmesh Android MVP", style = MaterialTheme.typography.headlineSmall)
                        SectionMenu(state = state, vm = vm)
                        StatusPanel(state = state)

                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f),
                        ) {
                            when (state.selectedSection) {
                                MainSection.SETTINGS -> SettingsView(
                                    state = state,
                                    vm = vm,
                                    onOpenFiles = { openFilesAtIronmeshRoot(vm) },
                                )
                                MainSection.WEB_UI -> WebUiSection(
                                    state = state,
                                    vm = vm,
                                )
                                MainSection.GALLERY -> GalleryView(
                                    state = state,
                                    vm = vm,
                                )
                            }
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
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SectionMenu(
    state: MainUiState,
    vm: MainViewModel,
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(
            selected = state.selectedSection == MainSection.SETTINGS,
            onClick = { vm.selectSection(MainSection.SETTINGS) },
            label = { Text("Settings") },
        )
        FilterChip(
            selected = state.selectedSection == MainSection.WEB_UI,
            onClick = { vm.selectSection(MainSection.WEB_UI) },
            label = { Text("Web UI") },
        )
        FilterChip(
            selected = state.selectedSection == MainSection.GALLERY,
            onClick = { vm.selectSection(MainSection.GALLERY) },
            label = { Text("Gallery") },
        )
    }
}

@Composable
private fun StatusPanel(state: MainUiState) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 1.dp,
        shape = RoundedCornerShape(16.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (state.loading || state.galleryLoading) {
                CircularProgressIndicator()
            }
            Text("Status: ${state.status}")
            if (state.objectBody.isNotBlank() && state.selectedSection == MainSection.SETTINGS) {
                Text("Object body:\n${state.objectBody}")
            }
        }
    }
}

@Composable
private fun SettingsView(
    state: MainUiState,
    vm: MainViewModel,
    onOpenFiles: () -> Unit,
) {
    val context = LocalContext.current
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        if (result.contents != null) {
            vm.updateBootstrapInput(result.contents)
        }
    }
    val folderPickerLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        handleFolderPickerResult(
            context = context,
            result = result,
            onResolvedSelection = { path, treeUri ->
                vm.updateNewSyncLocalFolderSelection(path, treeUri)
                vm.setStatus("Selected sync folder: $path")
            },
            onError = vm::setStatus,
        )
    }
    val onScanQr: () -> Unit = {
        scanLauncher.launch(
            ScanOptions().apply {
                setPrompt("Scan bootstrap bundle QR code")
                setBeepEnabled(false)
                setOrientationLocked(false)
            },
        )
    }
    val onPickLocalFolder: () -> Unit = {
        launchFolderPicker(
            launcher = folderPickerLauncher,
            onError = vm::setStatus,
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        ServerControls(
            state = state,
            vm = vm,
            onOpenFiles = onOpenFiles,
            onScanQr = onScanQr,
        )
        FolderSyncControls(
            state = state,
            vm = vm,
            onPickLocalFolder = onPickLocalFolder,
        )
    }
}

@Composable
private fun WebUiSection(
    state: MainUiState,
    vm: MainViewModel,
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Web UI", style = MaterialTheme.typography.titleMedium)

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = vm::startWebUi) {
                Text(if (state.webUiUrl.isBlank()) "Start Web UI" else "Restart Web UI")
            }
        }

        if (state.webUiUrl.isBlank()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                tonalElevation = 2.dp,
                shape = RoundedCornerShape(18.dp),
            ) {
                Text(
                    text = "Start the embedded Web UI to load it in this view.",
                    modifier = Modifier.padding(16.dp),
                )
            }
        } else {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                tonalElevation = 2.dp,
                shape = RoundedCornerShape(18.dp),
            ) {
                EmbeddedWebUi(
                    url = state.webUiUrl,
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
    }
}

@Composable
private fun GalleryView(
    state: MainUiState,
    vm: MainViewModel,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        GallerySection(state = state, vm = vm)
    }
}

@Composable
private fun ServerControls(
    state: MainUiState,
    vm: MainViewModel,
    onOpenFiles: () -> Unit,
    onScanQr: () -> Unit,
) {
    OutlinedTextField(
        modifier = Modifier.fillMaxWidth(),
        value = state.baseUrl,
        onValueChange = vm::updateBaseUrl,
        label = { Text("Server URL") },
        singleLine = true,
    )

    Text("Device Auth", style = MaterialTheme.typography.titleMedium)

    if (state.deviceAuthState.hasToken()) {
        Text("Enrolled device: ${state.deviceAuthState.deviceId}")
        if (!state.deviceAuthState.label.isNullOrBlank()) {
            Text("Label: ${state.deviceAuthState.label}")
        }
    } else {
        Text("This device is not enrolled yet.")
    }

    OutlinedTextField(
        modifier = Modifier.fillMaxWidth(),
        value = state.deviceLabelInput,
        onValueChange = vm::updateDeviceLabelInput,
        label = { Text("Device Label") },
        singleLine = true,
    )

    OutlinedTextField(
        modifier = Modifier.fillMaxWidth(),
        value = state.bootstrapInput,
        onValueChange = vm::updateBootstrapInput,
        label = { Text("Connection Bundle") },
        minLines = 4,
    )

    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = vm::enrollDevice) { Text("Enroll Device") }
        OutlinedButton(onClick = onScanQr) { Text("Scan QR") }
        OutlinedButton(onClick = vm::clearDeviceEnrollment) { Text("Clear Device Auth") }
    }

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
        Button(onClick = vm::putObject) { Text("PUT") }
        Button(onClick = vm::getObject) { Text("GET") }
    }

    Button(onClick = onOpenFiles) {
        Text("Open Files")
    }
}

@Composable
private fun FolderSyncControls(
    state: MainUiState,
    vm: MainViewModel,
    onPickLocalFolder: () -> Unit,
) {
    val profileStatuses = state.folderSyncStatus.profiles.associateBy { it.profileId }

    Text(
        "Folder Sync Profiles",
        style = MaterialTheme.typography.titleMedium,
    )

    Surface(
        modifier = Modifier.fillMaxWidth(),
        tonalElevation = 2.dp,
        shape = RoundedCornerShape(18.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text("Engine: ${state.folderSyncStatus.serviceState}")
            Text(state.folderSyncStatus.serviceMessage)
            if (state.folderSyncStatus.updatedUnixMs > 0L) {
                Text(
                    "Updated ${formatTimestamp(state.folderSyncStatus.updatedUnixMs)}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }

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
        OutlinedButton(onClick = onPickLocalFolder) {
            Text("Pick Folder")
        }
    }

    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = vm::runFolderSyncNow) { Text("Sync Now") }
    }

    if (state.syncProfiles.isEmpty()) {
        Text("No sync profiles configured.")
    }

    state.syncProfiles.forEach { profile ->
        val profileStatus = profileStatuses[profile.id]
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
                if (profileStatus != null) {
                    Text("Sync State: ${profileStatus.state}")
                    if (profileStatus.message.isNotBlank()) {
                        Text(
                            profileStatus.message,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                } else {
                    Text(
                        if (profile.enabled) "Sync State: waiting to start" else "Sync State: disabled",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
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

@Composable
private fun EmbeddedWebUi(
    url: String,
    modifier: Modifier = Modifier,
) {
    AndroidView(
        modifier = modifier,
        factory = { context ->
            WebView(context).apply {
                configureForIronmesh(url)
            }
        },
        update = { webView ->
            if (webView.url != url) {
                webView.loadUrl(url)
            }
        },
    )
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

private fun launchFolderPicker(
    launcher: ManagedActivityResultLauncher<Intent, ActivityResult>,
    onError: (String) -> Unit,
) {
    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
        addFlags(
            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION,
        )
    }

    try {
        launcher.launch(intent)
    } catch (_: ActivityNotFoundException) {
        onError("No compatible folder picker found on this device")
    }
}

private fun handleFolderPickerResult(
    context: android.content.Context,
    result: ActivityResult,
    onResolvedSelection: (String, String) -> Unit,
    onError: (String) -> Unit,
) {
    val treeUri = result.data?.data
    if (treeUri == null) {
        onError("Folder selection was cancelled")
        return
    }

    val grantFlags = result.data?.flags
        ?.and(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        ?: (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
    runCatching {
        context.contentResolver.takePersistableUriPermission(treeUri, grantFlags)
    }

    val resolvedPath = resolveTreeUriToFilesystemPath(treeUri)
    if (resolvedPath != null) {
        onResolvedSelection(resolvedPath, treeUri.toString())
    } else {
        onError(
            "Selected folder could not be mapped to a filesystem path. Please use a folder under shared storage such as DCIM or Documents.",
        )
    }
}

private fun resolveTreeUriToFilesystemPath(treeUri: Uri): String? {
    val documentId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull()
        ?: return null
    if (documentId.startsWith("raw:")) {
        return documentId.removePrefix("raw:")
    }

    val storageRoot = documentId.substringBefore(':', "")
    val relative = documentId.substringAfter(':', "")
        .split('/')
        .filter { it.isNotBlank() }

    val basePath = when {
        storageRoot.equals("primary", ignoreCase = true) -> "/storage/emulated/0"
        storageRoot.equals("home", ignoreCase = true) -> "/storage/emulated/0/Documents"
        storageRoot.length == 9 && storageRoot[4] == '-' -> "/storage/$storageRoot"
        else -> return null
    }

    return if (relative.isEmpty()) {
        basePath
    } else {
        buildString {
            append(basePath.trimEnd('/'))
            relative.forEach { segment ->
                append('/')
                append(segment)
            }
        }
    }
}

private fun loadDocumentThumbnail(
    contentResolver: ContentResolver,
    documentUri: Uri,
    sizePx: Int,
): Bitmap? {
    return runCatching {
        DocumentsContract.getDocumentThumbnail(
            contentResolver,
            documentUri,
            Point(sizePx, sizePx),
            null,
        )
    }.onFailure { error ->
        Log.w("MainActivity", "Thumbnail load failed for $documentUri: ${error.message}")
    }.getOrNull()
}

@SuppressLint("SetJavaScriptEnabled")
private fun WebView.configureForIronmesh(url: String) {
    settings.javaScriptEnabled = true
    settings.domStorageEnabled = true
    settings.allowFileAccess = false
    settings.allowContentAccess = false
    settings.mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
    webViewClient = WebViewClient()
    loadUrl(url)
}
