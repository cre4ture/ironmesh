package io.ironmesh.android

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.ContentResolver
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Point
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
import android.util.Log
import android.util.Size
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
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
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChange
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.viewmodel.compose.viewModel
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import io.ironmesh.android.data.RustSafBridge
import io.ironmesh.android.data.RustPreferencesBridge
import io.ironmesh.android.ui.GalleryViewMode
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
import kotlin.math.abs

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        RustSafBridge.initialize(applicationContext)
        RustPreferencesBridge.initialize(applicationContext)
        enableEdgeToEdge()

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val vm: MainViewModel = viewModel()
                    val state by vm.uiState
                    var openWebUiWhenReady by rememberSaveable { mutableStateOf(false) }

                    LaunchedEffect(openWebUiWhenReady, state.loading, state.webUiUrl) {
                        if (!openWebUiWhenReady || state.loading) {
                            return@LaunchedEffect
                        }

                        if (state.webUiUrl.isNotBlank()) {
                            startActivity(WebUiActivity.intent(this@MainActivity, state.webUiUrl))
                        }
                        openWebUiWhenReady = false
                    }

                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Image(
                                painter = painterResource(R.drawable.ic_ironmesh_mark),
                                contentDescription = "Ironmesh logo",
                                modifier = Modifier.size(44.dp),
                            )
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text("Ironmesh", style = MaterialTheme.typography.headlineSmall)
                                Text(
                                    "Android shell",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                        }
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
                                    onStartWebUi = {
                                        openWebUiWhenReady = true
                                        vm.startWebUi()
                                    },
                                    onRestartWebUi = {
                                        openWebUiWhenReady = true
                                        vm.startWebUi()
                                    },
                                    onOpenWebUi = { url ->
                                        startActivity(WebUiActivity.intent(this@MainActivity, url))
                                    },
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
                setPrompt("Scan bootstrap claim QR code")
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
    onStartWebUi: () -> Unit,
    onRestartWebUi: () -> Unit,
    onOpenWebUi: (String) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Web UI", style = MaterialTheme.typography.titleMedium)
        Text(
            text = "The client Web UI opens in a dedicated fullscreen screen. Use Android back to return here.",
        )

        if (state.webUiUrl.isBlank()) {
            Button(onClick = onStartWebUi) {
                Text("Open Fullscreen Web UI")
            }
            Surface(
                modifier = Modifier.fillMaxWidth(),
                tonalElevation = 2.dp,
                shape = RoundedCornerShape(18.dp),
            ) {
                Text(
                    text = "This starts the local Web UI and opens it fullscreen as soon as it is ready.",
                    modifier = Modifier.padding(16.dp),
                )
            }
        } else {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { onOpenWebUi(state.webUiUrl) }) {
                    Text("Open Fullscreen Web UI")
                }
                OutlinedButton(onClick = onRestartWebUi) {
                    Text("Restart Web UI")
                }
            }
            Surface(
                modifier = Modifier.fillMaxWidth(),
                tonalElevation = 2.dp,
                shape = RoundedCornerShape(18.dp),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text("Web UI ready", style = MaterialTheme.typography.titleSmall)
                    Text(state.webUiUrl, style = MaterialTheme.typography.bodySmall)
                    Text(
                        text = "Open it fullscreen to use the full screen area. Android back closes the Web UI and returns to this shell.",
                    )
                }
            }
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                tonalElevation = 0.dp,
                color = Color.Transparent,
            ) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "Web UI is no longer embedded inside the native tab.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
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

    Text("Device Identity", style = MaterialTheme.typography.titleMedium)

    if (state.deviceAuthState.hasClientIdentity()) {
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
        label = { Text("Bootstrap Claim or Bundle") },
        minLines = 4,
    )

    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = vm::enrollDevice) { Text("Enroll Device") }
        OutlinedButton(onClick = onScanQr) { Text("Scan QR") }
        OutlinedButton(onClick = vm::clearDeviceEnrollment) { Text("Clear Device Identity") }
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
    var fullscreenIndex by remember(state.galleryItems, state.galleryCurrentDirectoryPath) {
        mutableStateOf<Int?>(null)
    }

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
            selected = state.galleryMode == GalleryViewMode.FLATTENED_ALL_IMAGES,
            onClick = { vm.updateGalleryViewMode(GalleryViewMode.FLATTENED_ALL_IMAGES) },
            label = { Text("All Images") },
        )
        FilterChip(
            selected = state.galleryMode == GalleryViewMode.CURRENT_DIRECTORY,
            onClick = { vm.updateGalleryViewMode(GalleryViewMode.CURRENT_DIRECTORY) },
            label = { Text("Current Folder") },
        )
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

    if (state.galleryMode == GalleryViewMode.CURRENT_DIRECTORY) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            tonalElevation = 2.dp,
            shape = RoundedCornerShape(18.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "Current folder: ${state.galleryCurrentDirectoryPath}",
                    style = MaterialTheme.typography.titleSmall,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = vm::navigateGalleryToRoot) {
                        Text("Root")
                    }
                    OutlinedButton(
                        onClick = vm::navigateGalleryUp,
                        enabled = state.galleryBreadcrumbs.isNotEmpty(),
                    ) {
                        Text("Up")
                    }
                }
                if (state.galleryBreadcrumbs.isNotEmpty()) {
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(onClick = vm::navigateGalleryToRoot) {
                            Text("/")
                        }
                        state.galleryBreadcrumbs.forEachIndexed { index, breadcrumb ->
                            OutlinedButton(
                                onClick = { vm.navigateGalleryToBreadcrumb(index) },
                            ) {
                                Text(breadcrumb.label)
                            }
                        }
                    }
                }
                if (state.galleryDirectories.isNotEmpty()) {
                    Text("Folders", style = MaterialTheme.typography.titleSmall)
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        state.galleryDirectories.forEach { directory ->
                            OutlinedButton(onClick = { vm.openGalleryDirectory(directory) }) {
                                Text(directory.displayName)
                            }
                        }
                    }
                }
            }
        }
    }

    if (state.galleryLoading) {
        CircularProgressIndicator()
    } else if (state.galleryItems.isEmpty() && state.galleryDirectories.isEmpty()) {
        Text(
            if (state.galleryMode == GalleryViewMode.FLATTENED_ALL_IMAGES) {
                "No images loaded from the document provider."
            } else {
                "No images or nested folders found in the current directory."
            },
        )
    } else if (state.galleryItems.isEmpty()) {
        Text("No images in the current directory. Open a folder above or go up a level.")
    } else {
        GalleryGrid(
            items = state.galleryItems,
            onItemClick = { index -> fullscreenIndex = index },
        )
        Text(
            text = if (state.galleryMode == GalleryViewMode.FLATTENED_ALL_IMAGES) {
                "Pinch the gallery to change thumbnail size."
            } else {
                "Pinch the gallery to change thumbnail size. The fullscreen viewer only follows the current folder image list."
            },
            style = MaterialTheme.typography.bodySmall,
        )
    }

    val selectedIndex = fullscreenIndex
    if (selectedIndex != null && state.galleryItems.isNotEmpty()) {
        GalleryFullscreenViewer(
            items = state.galleryItems,
            initialIndex = selectedIndex.coerceIn(0, state.galleryItems.lastIndex),
            onDismiss = { fullscreenIndex = null },
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun GalleryGrid(
    items: List<GalleryImageItem>,
    onItemClick: (Int) -> Unit,
) {
    BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
        val density = LocalDensity.current
        val gap = 12.dp
        val autoColumns = when {
            maxWidth < 420.dp -> 2
            maxWidth < 800.dp -> 3
            else -> 4
        }
        var columns by rememberSaveable(autoColumns) { mutableIntStateOf(autoColumns) }
        val maxColumns = 6
        var accumulatedZoom by remember { mutableFloatStateOf(1f) }
        val clampedColumns = columns.coerceIn(1, maxColumns)
        if (clampedColumns != columns) {
            columns = clampedColumns
        }
        val cardWidth = with(density) {
            val availableWidthPx =
                (maxWidth.roundToPx() - gap.roundToPx() * (columns - 1)).coerceAtLeast(columns)
            (availableWidthPx / columns).toDp()
        }

        FlowRow(
            modifier = Modifier
                .fillMaxWidth()
                .galleryGridPinchGesture(
                    onPinch = { zoom ->
                        accumulatedZoom *= zoom
                        if (accumulatedZoom > 1.12f) {
                            columns = (columns - 1).coerceAtLeast(1)
                            accumulatedZoom = 1f
                        } else if (accumulatedZoom < 0.88f) {
                            columns = (columns + 1).coerceAtMost(maxColumns)
                            accumulatedZoom = 1f
                        }
                    },
                ),
            maxItemsInEachRow = columns,
            horizontalArrangement = Arrangement.spacedBy(gap),
            verticalArrangement = Arrangement.spacedBy(gap),
        ) {
            items.forEachIndexed { index, item ->
                GalleryCard(
                    item = item,
                    showDetails = columns < 3,
                    onClick = { onItemClick(index) },
                    modifier = Modifier.width(cardWidth),
                )
            }
        }
    }
}

@Composable
private fun GalleryCard(
    item: GalleryImageItem,
    showDetails: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.clickable(onClick = onClick),
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

            if (showDetails) {
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
}

@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class)
@Composable
private fun GalleryFullscreenViewer(
    items: List<GalleryImageItem>,
    initialIndex: Int,
    onDismiss: () -> Unit,
) {
    val zoomedPages = remember { mutableStateMapOf<Int, Boolean>() }
    val pagerState = rememberPagerState(
        initialPage = initialIndex,
        pageCount = { items.size },
    )
    BackHandler(onBack = onDismiss)

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = false,
        ),
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = Color.Black,
        ) {
            Box(modifier = Modifier.fillMaxSize()) {
                HorizontalPager(
                    state = pagerState,
                    userScrollEnabled = zoomedPages[pagerState.currentPage] != true,
                    modifier = Modifier.fillMaxSize(),
                ) { page ->
                    GalleryFullscreenPage(
                        item = items[page],
                        onZoomStateChanged = { zoomed ->
                            zoomedPages[page] = zoomed
                        },
                    )
                }

                Surface(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .fillMaxWidth()
                        .statusBarsPadding(),
                    color = Color.Black.copy(alpha = 0.55f),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        OutlinedButton(onClick = onDismiss) {
                            Text("Close")
                        }
                        Text(
                            text = items[pagerState.currentPage].displayName,
                            color = Color.White,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            text = "${pagerState.currentPage + 1}/${items.size}",
                            color = Color.White,
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }

                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth()
                        .navigationBarsPadding(),
                    color = Color.Black.copy(alpha = 0.55f),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        val item = items[pagerState.currentPage]
                        Text(
                            text = item.remotePath,
                            color = Color.White,
                            style = MaterialTheme.typography.bodyMedium,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        galleryMetaText(item)?.let { meta ->
                            Text(
                                text = meta,
                                color = Color.White.copy(alpha = 0.8f),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        item.createdAtUnixMs?.let { createdAt ->
                            Text(
                                text = "Created ${formatTimestamp(createdAt)}",
                                color = Color.White.copy(alpha = 0.8f),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        Text(
                            text = "Swipe left or right to browse",
                            color = Color.White.copy(alpha = 0.75f),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun GalleryFullscreenPage(
    item: GalleryImageItem,
    onZoomStateChanged: (Boolean) -> Unit,
) {
    val context = LocalContext.current
    val density = LocalDensity.current
    var scale by remember(item.documentUri) { mutableFloatStateOf(1f) }
    var offsetX by remember(item.documentUri) { mutableFloatStateOf(0f) }
    var offsetY by remember(item.documentUri) { mutableFloatStateOf(0f) }
    val bitmap by produceState<Bitmap?>(initialValue = null, item.documentUri) {
        value = withContext(Dispatchers.IO) {
            loadDocumentBitmap(
                contentResolver = context.contentResolver,
                documentUri = item.documentUri,
                maxDimensionPx = 2048,
            )
        }
    }

    LaunchedEffect(scale) {
        onZoomStateChanged(scale > 1.01f)
    }

    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .clipToBounds(),
        contentAlignment = Alignment.Center,
    ) {
        val widthPx = with(density) { maxWidth.toPx() }
        val heightPx = with(density) { maxHeight.toPx() }
        val loadedBitmap = bitmap
        if (loadedBitmap != null) {
            val fittedSize = fittedImageSize(
                imageWidth = loadedBitmap.width.toFloat(),
                imageHeight = loadedBitmap.height.toFloat(),
                containerWidth = widthPx,
                containerHeight = heightPx,
            )
            Image(
                bitmap = loadedBitmap.asImageBitmap(),
                contentDescription = item.displayName,
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .zoomableImageGesture(
                        gestureKey = item.documentUri,
                        fittedSize = fittedSize,
                        containerWidth = widthPx,
                        containerHeight = heightPx,
                        scale = { scale },
                        offset = { Offset(offsetX, offsetY) },
                        onTransform = { newScale, newOffset ->
                            scale = newScale
                            offsetX = newOffset.x
                            offsetY = newOffset.y
                        },
                    )
                    .graphicsLayer {
                        scaleX = scale
                        scaleY = scale
                        translationX = offsetX
                        translationY = offsetY
                    },
            )
        } else {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                CircularProgressIndicator(color = Color.White)
                Text(
                    text = "Loading image...",
                    color = Color.White,
                    style = MaterialTheme.typography.bodyMedium,
                )
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

private fun loadDocumentBitmap(
    contentResolver: ContentResolver,
    documentUri: Uri,
    maxDimensionPx: Int,
): Bitmap? {
    return runCatching {
        val bounds = BitmapFactory.Options().apply {
            inJustDecodeBounds = true
        }
        contentResolver.openInputStream(documentUri)?.use { input ->
            BitmapFactory.decodeStream(input, null, bounds)
        }

        val sampleSize = computeInSampleSize(
            width = bounds.outWidth,
            height = bounds.outHeight,
            maxDimensionPx = maxDimensionPx,
        )
        val decodeOptions = BitmapFactory.Options().apply {
            inSampleSize = sampleSize
        }
        contentResolver.openInputStream(documentUri)?.use { input ->
            BitmapFactory.decodeStream(input, null, decodeOptions)
        }
    }.onFailure { error ->
        Log.w("MainActivity", "Full image load failed for $documentUri: ${error.message}")
    }.getOrNull()
}

private fun computeInSampleSize(
    width: Int,
    height: Int,
    maxDimensionPx: Int,
): Int {
    if (width <= 0 || height <= 0 || maxDimensionPx <= 0) {
        return 1
    }

    var sampleSize = 1
    while (width / sampleSize > maxDimensionPx || height / sampleSize > maxDimensionPx) {
        sampleSize *= 2
    }
    return sampleSize.coerceAtLeast(1)
}

private fun Modifier.galleryGridPinchGesture(
    onPinch: (Float) -> Unit,
): Modifier = pointerInput(Unit) {
    awaitEachGesture {
        awaitFirstDown(requireUnconsumed = false)
        do {
            val event = awaitPointerEvent()
            val pointerCount = event.changes.count { it.pressed }
            if (pointerCount >= 2) {
                val zoom = event.calculateZoom()
                if (abs(zoom - 1f) > 0.01f) {
                    onPinch(zoom)
                    event.changes.forEach { change ->
                        if (change.pressed) {
                            change.consume()
                        }
                    }
                }
            }
        } while (event.changes.any { it.pressed })
    }
}

private fun Modifier.zoomableImageGesture(
    gestureKey: Any?,
    fittedSize: FittedImageSize,
    containerWidth: Float,
    containerHeight: Float,
    scale: () -> Float,
    offset: () -> Offset,
    onTransform: (Float, Offset) -> Unit,
): Modifier = pointerInput(gestureKey, fittedSize, containerWidth, containerHeight) {
    awaitEachGesture {
        awaitFirstDown(requireUnconsumed = false)
        do {
            val event = awaitPointerEvent()
            val pressedChanges = event.changes.filter { it.pressed }
            if (pressedChanges.isEmpty()) {
                break
            }

            val currentScale = scale()
            val currentOffset = offset()
            val zoomChange = if (pressedChanges.size >= 2) event.calculateZoom() else 1f
            val panChange = when {
                pressedChanges.size >= 2 -> event.calculatePan()
                currentScale > 1.01f -> pressedChanges.first().positionChange()
                else -> Offset.Zero
            }
            val nextScale = (currentScale * zoomChange).coerceIn(1f, 5f)
            val shouldHandleZoom = pressedChanges.size >= 2 && abs(zoomChange - 1f) > 0.01f
            val shouldHandlePan =
                panChange != Offset.Zero && (currentScale > 1.01f || nextScale > 1.01f)
            if (!shouldHandleZoom && !shouldHandlePan) {
                continue
            }

            onTransform(
                nextScale,
                boundedImageOffset(
                    scale = currentScale,
                    nextScale = nextScale,
                    offset = currentOffset,
                    pan = panChange,
                    fittedSize = fittedSize,
                    containerWidth = containerWidth,
                    containerHeight = containerHeight,
                ),
            )
            event.changes.forEach { change ->
                if (change.pressed) {
                    change.consume()
                }
            }
        } while (event.changes.any { it.pressed })
    }
}

private data class FittedImageSize(
    val width: Float,
    val height: Float,
)

private fun boundedImageOffset(
    scale: Float,
    nextScale: Float,
    offset: Offset,
    pan: Offset,
    fittedSize: FittedImageSize,
    containerWidth: Float,
    containerHeight: Float,
): Offset {
    if (nextScale <= 1.01f) {
        return Offset.Zero
    }

    val scaleChange = if (scale == 0f) 1f else nextScale / scale
    val rawOffset = Offset(
        x = (offset.x + pan.x) * scaleChange,
        y = (offset.y + pan.y) * scaleChange,
    )
    val maxOffsetX = ((fittedSize.width * nextScale) - containerWidth).coerceAtLeast(0f) / 2f
    val maxOffsetY = ((fittedSize.height * nextScale) - containerHeight).coerceAtLeast(0f) / 2f
    return Offset(
        x = rawOffset.x.coerceIn(-maxOffsetX, maxOffsetX),
        y = rawOffset.y.coerceIn(-maxOffsetY, maxOffsetY),
    )
}

private fun fittedImageSize(
    imageWidth: Float,
    imageHeight: Float,
    containerWidth: Float,
    containerHeight: Float,
): FittedImageSize {
    if (
        imageWidth <= 0f ||
        imageHeight <= 0f ||
        containerWidth <= 0f ||
        containerHeight <= 0f
    ) {
        return FittedImageSize(containerWidth, containerHeight)
    }

    val scale = minOf(containerWidth / imageWidth, containerHeight / imageHeight)
    return FittedImageSize(
        width = imageWidth * scale,
        height = imageHeight * scale,
    )
}
