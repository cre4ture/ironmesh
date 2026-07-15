package io.ironmesh.android

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import io.ironmesh.android.data.FolderSyncNetworkPolicy
import io.ironmesh.android.data.RustPreferencesBridge
import io.ironmesh.android.data.RustSafBridge
import io.ironmesh.android.ui.MainSection
import io.ironmesh.android.ui.MainViewModel
import io.ironmesh.android.ui.components.IronmeshAppShell
import io.ironmesh.android.ui.screens.HomeScreen
import io.ironmesh.android.ui.screens.LibraryScreen
import io.ironmesh.android.ui.screens.OnboardingScreen
import io.ironmesh.android.ui.screens.SettingsScreen
import io.ironmesh.android.ui.screens.SyncScreen
import io.ironmesh.android.ui.theme.IronmeshTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        RustSafBridge.initialize(applicationContext)
        RustPreferencesBridge.initialize(applicationContext)
        enableEdgeToEdge()

        setContent {
            val vm: MainViewModel = viewModel()
            val state by vm.uiState
            IronmeshTheme(accentColorHex = state.themeAccentColorHex) {
                val context = LocalContext.current
                val snackbarHostState = remember { SnackbarHostState() }
                var lastSnackbarMessage by rememberSaveable { mutableStateOf("") }
                var openWebUiWhenReady by rememberSaveable { mutableStateOf(false) }
                var existingProfilePermissionRequestAttempted by rememberSaveable { mutableStateOf(false) }

                val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
                    if (result.contents != null) {
                        vm.updateBootstrapInput(result.contents)
                    }
                }
                val photoAccessPermissionLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.RequestMultiplePermissions(),
                ) { grants ->
                    val denied = grants
                        .filterValues { granted -> !granted }
                        .keys
                        .toList()
                    if (denied.isEmpty()) {
                        Log.i("MainActivity", "Granted photo original-byte permissions for folder sync")
                        vm.setStatus("Photo metadata access granted for folder sync")
                    } else {
                        Log.i(
                            "MainActivity",
                            "Photo original-byte permissions denied: ${denied.joinToString(", ")}",
                        )
                        vm.setStatus("Photo GPS EXIF may be stripped until photo permissions are granted")
                    }
                }
                val wifiNamePermissionLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.RequestMultiplePermissions(),
                ) { grants ->
                    val denied = grants
                        .filterValues { granted -> !granted }
                        .keys
                        .toList()
                    if (denied.isEmpty()) {
                        vm.setStatus("Wi-Fi name access granted for restricted sync rules")
                    } else {
                        vm.setStatus(
                            "Allowed Wi-Fi names need Android Wi-Fi/location access before they can be enforced",
                        )
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
                            requestOriginalPhotoAccessIfNeeded(context, photoAccessPermissionLauncher)
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
                val onEnsureWifiNameAccess: (FolderSyncNetworkPolicy) -> Unit = { policy ->
                    requestWifiNameAccessIfNeeded(
                        context = context,
                        launcher = wifiNamePermissionLauncher,
                        policy = policy,
                    )
                }
                val onOpenWebConsole: () -> Unit = {
                    if (state.webUiUrl.isNotBlank() && !state.loading) {
                        openWebUi(state.webUiUrl, vm::setStatus)
                    } else {
                        openWebUiWhenReady = true
                        vm.startWebUi()
                    }
                }
                val hasPhotoAccess = missingOriginalPhotoAccessPermissions(context).isEmpty()
                val hasWifiNamePermissions = missingWifiNameAccessPermissions(context).isEmpty()
                val isLocationEnabled = isDeviceLocationEnabled(context)

                LaunchedEffect(openWebUiWhenReady, state.loading, state.webUiUrl) {
                    if (!openWebUiWhenReady || state.loading) {
                        return@LaunchedEffect
                    }
                    if (state.webUiUrl.isNotBlank()) {
                        openWebUi(state.webUiUrl, vm::setStatus)
                    }
                    openWebUiWhenReady = false
                }

                LaunchedEffect(state.syncProfiles) {
                    if (existingProfilePermissionRequestAttempted || state.syncProfiles.isEmpty()) {
                        return@LaunchedEffect
                    }

                    existingProfilePermissionRequestAttempted = true
                    requestOriginalPhotoAccessIfNeeded(context, photoAccessPermissionLauncher)
                }

                LaunchedEffect(state.status) {
                    if (
                        state.status.isBlank() ||
                        state.status == "Ready" ||
                        state.status == lastSnackbarMessage
                    ) {
                        return@LaunchedEffect
                    }
                    lastSnackbarMessage = state.status
                    snackbarHostState.showSnackbar(state.status)
                }

                if (!state.deviceAuthState.hasClientIdentity()) {
                    Scaffold(
                        snackbarHost = { SnackbarHost(snackbarHostState) },
                    ) { _ ->
                        OnboardingScreen(
                            state = state,
                            onDeviceLabelChange = vm::updateDeviceLabelInput,
                            onBootstrapInputChange = vm::updateBootstrapInput,
                            onScanQr = onScanQr,
                            onEnroll = vm::enrollDevice,
                        )
                    }
                } else {
                    IronmeshAppShell(
                        selectedSection = state.selectedSection,
                        onSelectSection = vm::selectSection,
                        snackbarHostState = snackbarHostState,
                        deviceLabel = state.deviceAuthState.label,
                    ) { contentModifier ->
                        Box(modifier = contentModifier) {
                            when (state.selectedSection) {
                                MainSection.HOME -> HomeScreen(
                                    state = state,
                                    onRunSyncNow = vm::runFolderSyncNow,
                                    onOpenWebConsole = onOpenWebConsole,
                                    onOpenSync = { vm.selectSection(MainSection.SYNC) },
                                    onSelectSection = vm::selectSection,
                                )

                                MainSection.SYNC -> SyncScreen(
                                    state = state,
                                    vm = vm,
                                    onPickLocalFolder = onPickLocalFolder,
                                    onEnsureWifiNameAccess = onEnsureWifiNameAccess,
                                )

                                MainSection.LIBRARY -> LibraryScreen(
                                    state = state,
                                    vm = vm,
                                )

                                MainSection.SETTINGS -> SettingsScreen(
                                    state = state,
                                    hasPhotoAccess = hasPhotoAccess,
                                    hasWifiNamePermissions = hasWifiNamePermissions,
                                    isLocationEnabled = isLocationEnabled,
                                    onRequestPhotoAccess = {
                                        requestOriginalPhotoAccessIfNeeded(
                                            context,
                                            photoAccessPermissionLauncher,
                                        )
                                    },
                                    onRequestWifiNameAccess = {
                                        val missing = missingWifiNameAccessPermissions(context)
                                        if (missing.isNotEmpty()) {
                                            wifiNamePermissionLauncher.launch(missing)
                                        }
                                    },
                                    onOpenLocationSettings = {
                                        if (!openLocationSettings(context)) {
                                            vm.setStatus("Unable to open Android location settings")
                                        }
                                    },
                                    onOpenFiles = { openFilesAtIronmeshRoot(vm) },
                                    onOpenWebConsole = onOpenWebConsole,
                                    onClearEnrollment = vm::clearDeviceEnrollment,
                                    onThemeAccentColorChange = vm::updateThemeAccentColor,
                                    onKeyChange = vm::updateKey,
                                    onPayloadChange = vm::updatePayload,
                                    onPutObject = vm::putObject,
                                    onGetObject = vm::getObject,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private fun openWebUi(
        webUiUrl: String,
        onStatus: (String) -> Unit,
    ) {
        if (webUiUrl.isBlank()) {
            onStatus("Web UI is not ready yet")
            return
        }

        val customTabsIntent = CustomTabsIntent.Builder()
            .setShowTitle(false)
            .setUrlBarHidingEnabled(true)
            .setShareState(CustomTabsIntent.SHARE_STATE_OFF)
            .build()

        try {
            customTabsIntent.launchUrl(this, Uri.parse(webUiUrl))
            onStatus("Opened Web UI in a browser-powered tab")
        } catch (_: ActivityNotFoundException) {
            startActivity(WebUiActivity.intent(this, webUiUrl))
            onStatus("No compatible browser tab found, using the embedded Web UI")
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
