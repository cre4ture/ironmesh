package io.ironmesh.android.ui

import android.app.Application
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.viewModelScope
import io.ironmesh.android.api.StoreIndexEntry
import io.ironmesh.android.api.StoreIndexResponse
import io.ironmesh.android.api.StoreIndexSortOrder
import io.ironmesh.android.data.ConnectionRouteSnapshot
import io.ironmesh.android.data.DeviceAuthState
import io.ironmesh.android.data.EnrollmentAccessVerification
import io.ironmesh.android.data.EmbeddedWebUiSession
import io.ironmesh.android.data.DeviceIdentityStorageException
import io.ironmesh.android.data.FolderSyncConfig
import io.ironmesh.android.data.AppConnectionStatus
import io.ironmesh.android.data.FolderSyncNetworkPolicy
import io.ironmesh.android.data.FolderSyncModificationRecord
import io.ironmesh.android.data.FolderSyncServiceStatus
import io.ironmesh.android.ui.screens.ThumbnailBitmapCache
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import io.ironmesh.android.data.parseAllowedWifiSsidsInput
import io.ironmesh.android.work.FolderSyncForegroundService
import io.ironmesh.android.ui.theme.DEFAULT_IRONMESH_ACCENT_COLOR_HEX
import io.ironmesh.android.ui.theme.normalizeIronmeshAccentColorHex
import io.ironmesh.android.work.FolderSyncScheduler
import io.ironmesh.android.work.FolderSyncNetworkGate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

enum class GallerySortOption {
    CREATION_TIME,
    NAME,
}

enum class GalleryViewMode {
    FLATTENED_ALL_IMAGES,
    CURRENT_DIRECTORY,
}

enum class MainSection {
    HOME,
    CONNECTIVITY,
    SYNC,
    LIBRARY,
    GALLERY_MAP,
    SETTINGS,
}

enum class FolderSyncActivityFilter {
    ALL,
    UPLOADS,
    DOWNLOADS,
    DELETES,
}

private const val GALLERY_ROOT_DOCUMENT_ID = "dir:"
private const val GALLERY_ROOT_PATH = "/"
private const val GALLERY_PAGE_SIZE = 32
private const val GALLERY_PAGE_PRELOAD_RADIUS = 1
private const val GALLERY_PAGE_KEEP_RADIUS = 2
private const val GALLERY_FLATTENED_DEPTH = 64
private const val FOLDER_SYNC_HISTORY_PAGE_SIZE = 20
private const val FOLDER_SYNC_HISTORY_REFRESH_MS = 5_000L
private const val CONNECTION_ROUTE_SNAPSHOT_POLL_MS = 5_000L
private const val ENROLLMENT_VERIFICATION_POLL_MS = 5_000L
private const val ENROLLMENT_LOG_TAG = "EnrollmentDiagnostics"

data class FolderSyncHistoryState(
    val expanded: Boolean = false,
    val records: List<FolderSyncModificationRecord> = emptyList(),
    val nextBeforeId: Long? = null,
    val filter: FolderSyncActivityFilter = FolderSyncActivityFilter.ALL,
    val loading: Boolean = false,
    val error: String? = null,
    val lastLoadedUnixMs: Long = 0L,
)

data class GalleryImageItem(
    val documentUri: Uri,
    val displayName: String,
    val remotePath: String,
    val mimeType: String,
    val createdAtUnixMs: Long? = null,
    val width: Int? = null,
    val height: Int? = null,
    val thumbnailStatus: String? = null,
)

data class GalleryDirectoryItem(
    val documentId: String,
    val displayName: String,
    val pathLabel: String,
)

data class GalleryBreadcrumbItem(
    val documentId: String,
    val label: String,
    val pathLabel: String,
)

data class GalleryCollectionState(
    val totalItemCount: Int,
    val pageSize: Int,
    val pageCount: Int,
)

enum class GalleryPageStatus {
    LOADING,
    READY,
    ERROR,
}

data class GalleryPageState(
    val status: GalleryPageStatus,
    val items: List<GalleryImageItem> = emptyList(),
    val error: String? = null,
)

data class MainUiState(
    val deviceAuthState: DeviceAuthState = DeviceAuthState(),
    val bootstrapInput: String = "",
    val deviceLabelInput: String = "",
    val enrollmentDiagnostics: List<EnrollmentDiagnosticStep> = emptyList(),
    val key: String = "demo-key",
    val payload: String = "hello from android",
    val status: String = "Ready",
    val objectBody: String = "",
    val syncProfiles: List<FolderSyncConfig> = emptyList(),
    val folderSyncStatus: FolderSyncServiceStatus = FolderSyncServiceStatus(),
    val appConnectionStatus: AppConnectionStatus = AppConnectionStatus(),
    val folderSyncHistory: Map<String, FolderSyncHistoryState> = emptyMap(),
    val newSyncLabel: String = "",
    val newSyncPrefix: String = "",
    val newSyncLocalFolder: String = "",
    val newSyncLocalFolderTreeUri: String? = null,
    val newSyncAllowWifi: Boolean = true,
    val newSyncAllowCellular: Boolean = true,
    val newSyncAllowOtherConnections: Boolean = true,
    val newSyncAllowRoaming: Boolean = false,
    val newSyncAllowedWifiSsids: String = "",
    val selectedSection: MainSection = MainSection.HOME,
    val connectionRoutes: ConnectionRouteSnapshot? = null,
    val connectionRoutesLoading: Boolean = false,
    val connectionRoutesError: String? = null,
    val connectionRoutesLastLoadedUnixMs: Long = 0L,
    val webUiSession: EmbeddedWebUiSession? = null,
    val galleryMode: GalleryViewMode = GalleryViewMode.FLATTENED_ALL_IMAGES,
    val galleryCollection: GalleryCollectionState? = null,
    val galleryPages: Map<Int, GalleryPageState> = emptyMap(),
    val galleryDirectories: List<GalleryDirectoryItem> = emptyList(),
    val galleryBreadcrumbs: List<GalleryBreadcrumbItem> = emptyList(),
    val galleryCurrentDirectoryDocumentId: String = GALLERY_ROOT_DOCUMENT_ID,
    val galleryCurrentDirectoryPath: String = GALLERY_ROOT_PATH,
    val gallerySort: GallerySortOption = GallerySortOption.CREATION_TIME,
    val themeAccentColorHex: String = DEFAULT_IRONMESH_ACCENT_COLOR_HEX,
    val galleryLoading: Boolean = false,
    val loading: Boolean = false,
)

class MainViewModel(
    application: Application,
) : AndroidViewModel(application) {

    private val repository = IronmeshRepository()
    private var galleryRequestVersion = 0
    private var pinnedGalleryItemIndex: Int? = null
    private var connectionRoutesMonitorJob: Job? = null
    private var enrollmentVerificationMonitorJob: Job? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile
    private var processLifecycleObserverActive = true
    private var processLifecycleObserverRegistered = false
    private val processLifecycleObserver = LifecycleEventObserver { _, event ->
        if (event == Lifecycle.Event.ON_STOP) {
            repository.stopWebUi()
            uiState.value = uiState.value.copy(webUiSession = null)
        }
    }

    var uiState = androidx.compose.runtime.mutableStateOf(MainUiState())
        private set

    init {
        val persistedProfiles = IronmeshPreferences.getFolderSyncConfigs(getApplication())
        val persistedDeviceAuthResult = runCatching {
            IronmeshPreferences.getDeviceAuthState(getApplication())
        }
        val persistedDeviceAuth = persistedDeviceAuthResult.getOrDefault(DeviceAuthState())
        val persistedGalleryViewMode = IronmeshPreferences.getGalleryViewMode(getApplication())
        val persistedConnectionStatus = IronmeshPreferences.getAppConnectionStatus(getApplication())
        val persistedThemeAccentColor = IronmeshPreferences.getThemeAccentColor(getApplication())
        uiState.value = uiState.value.copy(
            syncProfiles = persistedProfiles,
            deviceAuthState = persistedDeviceAuth,
            deviceLabelInput = persistedDeviceAuth.label.orEmpty(),
            galleryMode = persistedGalleryViewMode,
            appConnectionStatus = persistedConnectionStatus,
            themeAccentColorHex = persistedThemeAccentColor,
            status = persistedDeviceAuthResult.exceptionOrNull()?.let { error ->
                "Device identity unavailable: ${error.message}"
            } ?: uiState.value.status,
        )
        FolderSyncScheduler.reschedule(getApplication())
        observeFolderSyncStatus()
        registerProcessLifecycleObserver()
    }

    override fun onCleared() {
        processLifecycleObserverActive = false
        unregisterProcessLifecycleObserver()
        stopEnrollmentVerificationMonitor()
        repository.stopWebUi()
        super.onCleared()
    }

    private fun registerProcessLifecycleObserver() {
        runOnMainThread {
            if (processLifecycleObserverActive && !processLifecycleObserverRegistered) {
                ProcessLifecycleOwner.get().lifecycle.addObserver(processLifecycleObserver)
                processLifecycleObserverRegistered = true
            }
        }
    }

    private fun unregisterProcessLifecycleObserver() {
        runOnMainThread {
            if (processLifecycleObserverRegistered) {
                ProcessLifecycleOwner.get().lifecycle.removeObserver(processLifecycleObserver)
                processLifecycleObserverRegistered = false
            }
        }
    }

    private fun runOnMainThread(action: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            action()
        } else {
            mainHandler.post(action)
        }
    }

    fun updateKey(value: String) {
        uiState.value = uiState.value.copy(key = value)
    }

    fun updateBootstrapInput(value: String) {
        uiState.value = uiState.value.copy(bootstrapInput = value)
    }

    fun updateDeviceLabelInput(value: String) {
        uiState.value = uiState.value.copy(deviceLabelInput = value)
    }

    fun updatePayload(value: String) {
        uiState.value = uiState.value.copy(payload = value)
    }

    fun updateThemeAccentColor(value: String) {
        val normalized = normalizeIronmeshAccentColorHex(value) ?: return
        IronmeshPreferences.setThemeAccentColor(getApplication(), normalized)
        uiState.value = uiState.value.copy(themeAccentColorHex = normalized)
    }

    fun putObject() {
        execute("Uploading object...") {
            val statusCode = repository.putObject(
                currentConnectionInput(),
                uiState.value.key,
                uiState.value.payload,
                currentServerCaPem(),
                currentClientIdentityJson(),
            )
            "PUT ok: HTTP $statusCode"
        }
    }

    fun getObject() {
        execute("Downloading object...") {
            val body = repository.getObject(
                currentConnectionInput(),
                uiState.value.key,
                serverCaPem = currentServerCaPem(),
                clientIdentityJson = currentClientIdentityJson(),
            )
            uiState.value = uiState.value.copy(objectBody = body)
            "GET ok: ${body.length} bytes"
        }
    }

    fun setStatus(message: String) {
        uiState.value = uiState.value.copy(status = message)
    }

    fun updateNewSyncLabel(value: String) {
        uiState.value = uiState.value.copy(newSyncLabel = value)
    }

    fun updateNewSyncPrefix(value: String) {
        uiState.value = uiState.value.copy(newSyncPrefix = value)
    }

    fun updateNewSyncLocalFolder(value: String) {
        uiState.value = uiState.value.copy(
            newSyncLocalFolder = value,
            newSyncLocalFolderTreeUri = null,
        )
    }

    fun updateNewSyncLocalFolderSelection(
        localFolder: String,
        treeUri: String?,
    ) {
        uiState.value = uiState.value.copy(
            newSyncLocalFolder = localFolder,
            newSyncLocalFolderTreeUri = treeUri,
        )
    }

    fun updateNewSyncAllowWifi(value: Boolean) {
        uiState.value = uiState.value.copy(newSyncAllowWifi = value)
    }

    fun updateNewSyncAllowCellular(value: Boolean) {
        uiState.value = uiState.value.copy(newSyncAllowCellular = value)
    }

    fun updateNewSyncAllowOtherConnections(value: Boolean) {
        uiState.value = uiState.value.copy(newSyncAllowOtherConnections = value)
    }

    fun updateNewSyncAllowRoaming(value: Boolean) {
        uiState.value = uiState.value.copy(newSyncAllowRoaming = value)
    }

    fun updateNewSyncAllowedWifiSsids(value: String) {
        uiState.value = uiState.value.copy(newSyncAllowedWifiSsids = value)
    }

    fun selectSection(section: MainSection) {
        val wasShowingGalleryMap = uiState.value.selectedSection == MainSection.GALLERY_MAP
        if (wasShowingGalleryMap && section != MainSection.GALLERY_MAP) {
            repository.stopWebUi()
            uiState.value = uiState.value.copy(webUiSession = null)
        }
        uiState.value = uiState.value.copy(selectedSection = section)
        if (section == MainSection.CONNECTIVITY) {
            startConnectionRoutesMonitor()
        } else {
            stopConnectionRoutesMonitor()
        }
        if (section == MainSection.SYNC) {
            refreshExpandedFolderSyncHistory(force = true)
        }
        if (
            section == MainSection.LIBRARY &&
            uiState.value.galleryCollection == null &&
            uiState.value.galleryDirectories.isEmpty() &&
            !uiState.value.galleryLoading
        ) {
            refreshGallery()
        }
        if (section == MainSection.GALLERY_MAP && uiState.value.webUiSession == null && !uiState.value.loading) {
            startWebUi()
        }
    }

    fun refreshConnectionRoutes() {
        stopConnectionRoutesMonitor()
        viewModelScope.launch {
            loadConnectionRoutes(
                refresh = true,
                showLoading = true,
                statusOnFailure = true,
            )
            if (uiState.value.selectedSection == MainSection.CONNECTIVITY) {
                startConnectionRoutesMonitor()
            }
        }
    }

    fun refreshGallery() {
        ThumbnailBitmapCache.clear()
        val request = currentGalleryRequest(pageSize = uiState.value.galleryCollection?.pageSize ?: GALLERY_PAGE_SIZE)
        val requestVersion = nextGalleryRequestVersion()
        pinnedGalleryItemIndex = null
        uiState.value = uiState.value.copy(
            galleryLoading = true,
            galleryCollection = null,
            galleryPages = emptyMap(),
            status = "Loading gallery...",
        )
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    loadGalleryState(request)
                }
            }
                .onSuccess { snapshot ->
                    if (!isCurrentGalleryRequest(requestVersion)) {
                        return@onSuccess
                    }
                    val firstPage = snapshot.firstPageItems
                    uiState.value = uiState.value.copy(
                        galleryCollection = snapshot.collection,
                        galleryPages = if (firstPage.isEmpty()) {
                            emptyMap()
                        } else {
                            mapOf(
                                0 to GalleryPageState(
                                    status = GalleryPageStatus.READY,
                                    items = firstPage,
                                ),
                            )
                        },
                        galleryDirectories = snapshot.directories,
                        galleryBreadcrumbs = snapshot.breadcrumbs,
                        galleryCurrentDirectoryDocumentId = snapshot.currentDirectoryDocumentId,
                        galleryCurrentDirectoryPath = snapshot.currentDirectoryPath,
                        galleryLoading = false,
                        status = when (snapshot.mode) {
                            GalleryViewMode.FLATTENED_ALL_IMAGES ->
                                "Gallery loaded: ${snapshot.collection.totalItemCount} images"
                            GalleryViewMode.CURRENT_DIRECTORY ->
                                "Gallery loaded: ${snapshot.collection.totalItemCount} images, ${snapshot.directories.size} folders in ${snapshot.currentDirectoryPath}"
                        },
                    )
                    updateVisibleGalleryPages(setOf(0))
                }
                .onFailure { error ->
                    if (!isCurrentGalleryRequest(requestVersion)) {
                        return@onFailure
                    }
                    uiState.value = uiState.value.copy(
                        galleryLoading = false,
                        status = "Error: ${error.message}",
                    )
                }
        }
    }

    fun updateGallerySort(sort: GallerySortOption) {
        if (uiState.value.gallerySort == sort) {
            return
        }
        uiState.value = uiState.value.copy(
            gallerySort = sort,
            galleryCollection = null,
            galleryPages = emptyMap(),
        )
        refreshGallery()
    }

    fun updateGalleryViewMode(mode: GalleryViewMode) {
        if (uiState.value.galleryMode == mode) {
            return
        }
        IronmeshPreferences.setGalleryViewMode(getApplication(), mode)
        uiState.value = uiState.value.copy(
            galleryMode = mode,
            galleryCollection = null,
            galleryPages = emptyMap(),
            galleryDirectories = emptyList(),
            galleryBreadcrumbs = emptyList(),
            galleryCurrentDirectoryDocumentId = GALLERY_ROOT_DOCUMENT_ID,
            galleryCurrentDirectoryPath = GALLERY_ROOT_PATH,
        )
        refreshGallery()
    }

    fun openGalleryDirectory(directory: GalleryDirectoryItem) {
        val nextBreadcrumbs = if (uiState.value.galleryMode == GalleryViewMode.CURRENT_DIRECTORY) {
            uiState.value.galleryBreadcrumbs + GalleryBreadcrumbItem(
                documentId = directory.documentId,
                label = directory.displayName,
                pathLabel = directory.pathLabel,
            )
        } else {
            emptyList()
        }
        uiState.value = uiState.value.copy(
            galleryCollection = null,
            galleryPages = emptyMap(),
            galleryBreadcrumbs = nextBreadcrumbs,
            galleryCurrentDirectoryDocumentId = directory.documentId,
            galleryCurrentDirectoryPath = directory.pathLabel,
        )
        refreshGallery()
    }

    fun navigateGalleryToRoot() {
        if (
            uiState.value.galleryCurrentDirectoryDocumentId == GALLERY_ROOT_DOCUMENT_ID &&
            uiState.value.galleryCurrentDirectoryPath == GALLERY_ROOT_PATH
        ) {
            return
        }
        uiState.value = uiState.value.copy(
            galleryCollection = null,
            galleryPages = emptyMap(),
            galleryBreadcrumbs = emptyList(),
            galleryCurrentDirectoryDocumentId = GALLERY_ROOT_DOCUMENT_ID,
            galleryCurrentDirectoryPath = GALLERY_ROOT_PATH,
        )
        refreshGallery()
    }

    fun navigateGalleryUp() {
        if (uiState.value.galleryBreadcrumbs.isEmpty()) {
            navigateGalleryToRoot()
            return
        }
        val nextBreadcrumbs = uiState.value.galleryBreadcrumbs.dropLast(1)
        val nextCurrent = nextBreadcrumbs.lastOrNull()
        uiState.value = uiState.value.copy(
            galleryCollection = null,
            galleryPages = emptyMap(),
            galleryBreadcrumbs = nextBreadcrumbs,
            galleryCurrentDirectoryDocumentId = nextCurrent?.documentId ?: GALLERY_ROOT_DOCUMENT_ID,
            galleryCurrentDirectoryPath = nextCurrent?.pathLabel ?: GALLERY_ROOT_PATH,
        )
        refreshGallery()
    }

    fun navigateGalleryToBreadcrumb(index: Int) {
        if (index < 0) {
            navigateGalleryToRoot()
            return
        }
        val nextBreadcrumbs = uiState.value.galleryBreadcrumbs.take(index + 1)
        val nextCurrent = nextBreadcrumbs.lastOrNull()
        uiState.value = uiState.value.copy(
            galleryCollection = null,
            galleryPages = emptyMap(),
            galleryBreadcrumbs = nextBreadcrumbs,
            galleryCurrentDirectoryDocumentId = nextCurrent?.documentId ?: GALLERY_ROOT_DOCUMENT_ID,
            galleryCurrentDirectoryPath = nextCurrent?.pathLabel ?: GALLERY_ROOT_PATH,
        )
        refreshGallery()
    }

    fun galleryItemAt(index: Int): GalleryImageItem? {
        val collection = uiState.value.galleryCollection ?: return null
        if (index < 0 || index >= collection.totalItemCount) {
            return null
        }
        val page = uiState.value.galleryPages[pageIndexForGalleryEntry(index, collection.pageSize)]
            ?: return null
        if (page.status != GalleryPageStatus.READY) {
            return null
        }
        return page.items[galleryEntryWithinPage(index, collection.pageSize)]
    }

    fun pinGalleryItem(index: Int?) {
        pinnedGalleryItemIndex = index?.takeIf { it >= 0 }
    }

    fun ensureGalleryItemLoaded(index: Int) {
        val collection = uiState.value.galleryCollection ?: return
        if (index < 0 || index >= collection.totalItemCount) {
            return
        }
        ensureGalleryPageLoaded(pageIndexForGalleryEntry(index, collection.pageSize))
    }

    fun retryGalleryPage(pageIndex: Int) {
        ensureGalleryPageLoaded(pageIndex, force = true)
    }

    fun updateVisibleGalleryPages(visiblePageIndices: Set<Int>) {
        val collection = uiState.value.galleryCollection ?: return
        if (collection.pageCount == 0) {
            return
        }

        val visible = visiblePageIndices
            .filter { it in 0 until collection.pageCount }
            .sorted()
        val pinnedPageIndex = pinnedGalleryItemIndex?.let {
            pageIndexForGalleryEntry(it, collection.pageSize)
        }
        val minVisible = visible.firstOrNull() ?: pinnedPageIndex ?: 0
        val maxVisible = visible.lastOrNull() ?: pinnedPageIndex ?: 0
        val rangeMin = pinnedPageIndex?.let { minOf(minVisible, it) } ?: minVisible
        val rangeMax = pinnedPageIndex?.let { maxOf(maxVisible, it) } ?: maxVisible
        val preloadStart = (rangeMin - GALLERY_PAGE_PRELOAD_RADIUS).coerceAtLeast(0)
        val preloadEnd = (rangeMax + GALLERY_PAGE_PRELOAD_RADIUS).coerceAtMost(collection.pageCount - 1)
        val keepStart = (rangeMin - GALLERY_PAGE_KEEP_RADIUS).coerceAtLeast(0)
        val keepEnd = (rangeMax + GALLERY_PAGE_KEEP_RADIUS).coerceAtMost(collection.pageCount - 1)

        for (pageIndex in preloadStart..preloadEnd) {
            ensureGalleryPageLoaded(pageIndex)
        }

        val nextPages = uiState.value.galleryPages.filterKeys { pageIndex ->
            pageIndex in keepStart..keepEnd ||
                uiState.value.galleryPages[pageIndex]?.status == GalleryPageStatus.LOADING
        }
        if (nextPages.size != uiState.value.galleryPages.size) {
            uiState.value = uiState.value.copy(galleryPages = nextPages)
        }
    }

    private fun ensureGalleryPageLoaded(
        pageIndex: Int,
        force: Boolean = false,
    ) {
        val currentState = uiState.value
        val collection = currentState.galleryCollection ?: return
        if (pageIndex < 0 || pageIndex >= collection.pageCount) {
            return
        }

        val existing = currentState.galleryPages[pageIndex]
        if (!force && (existing?.status == GalleryPageStatus.READY || existing?.status == GalleryPageStatus.LOADING)) {
            return
        }

        val request = currentGalleryRequest(pageSize = collection.pageSize)
        val requestVersion = galleryRequestVersion
        uiState.value = currentState.copy(
            galleryPages = currentState.galleryPages.toMutableMap().apply {
                put(
                    pageIndex,
                    GalleryPageState(
                        status = GalleryPageStatus.LOADING,
                        items = existing?.items.orEmpty(),
                    ),
                )
            },
        )

        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    loadGalleryPage(
                        request = request,
                        pageIndex = pageIndex,
                    )
                }
            }
                .onSuccess { response ->
                    if (!isCurrentGalleryRequest(requestVersion)) {
                        return@onSuccess
                    }
                    val items = response.entries.mapNotNull(::galleryImageItemFromEntry)
                    val nextCollection = collection.copy(
                        totalItemCount = response.total_entry_count.coerceAtLeast(items.size),
                        pageCount = resolveGalleryPageCount(
                            totalItemCount = response.total_entry_count.coerceAtLeast(items.size),
                            pageSize = collection.pageSize,
                        ),
                    )
                    uiState.value = uiState.value.copy(
                        galleryCollection = nextCollection,
                        galleryPages = uiState.value.galleryPages.toMutableMap().apply {
                            put(
                                pageIndex,
                                GalleryPageState(
                                    status = GalleryPageStatus.READY,
                                    items = items,
                                ),
                            )
                        },
                    )
                }
                .onFailure { error ->
                    if (!isCurrentGalleryRequest(requestVersion)) {
                        return@onFailure
                    }
                    uiState.value = uiState.value.copy(
                        galleryPages = uiState.value.galleryPages.toMutableMap().apply {
                            put(
                                pageIndex,
                                GalleryPageState(
                                    status = GalleryPageStatus.ERROR,
                                    error = error.message ?: "Failed to load gallery page",
                                ),
                            )
                        },
                    )
                }
        }
    }

    fun addFolderSyncProfile(): FolderSyncNetworkPolicy? {
        val localFolder = uiState.value.newSyncLocalFolder.trim()
        if (localFolder.isBlank()) {
            setStatus("Error: Local folder path is required")
            return null
        }

        val prefix = uiState.value.newSyncPrefix.trim().trim('/').replace('\\', '/')
        val label = uiState.value.newSyncLabel.trim().ifBlank {
            localFolder.substringAfterLast('/').ifBlank { "Sync Profile" }
        }
        val networkPolicy = FolderSyncNetworkPolicy(
            allowWifi = uiState.value.newSyncAllowWifi,
            allowCellular = uiState.value.newSyncAllowCellular,
            allowOtherConnections = uiState.value.newSyncAllowOtherConnections,
            allowRoaming = uiState.value.newSyncAllowRoaming,
            allowedWifiSsids = parseAllowedWifiSsidsInput(uiState.value.newSyncAllowedWifiSsids),
        ).normalized()
        if (!networkPolicy.hasAnyAllowedTransport()) {
            setStatus("Error: Select at least one allowed network type")
            return null
        }

        val profile = FolderSyncConfig(
            id = UUID.randomUUID().toString(),
            label = label,
            prefix = prefix,
            localFolder = localFolder,
            localFolderTreeUri = uiState.value.newSyncLocalFolderTreeUri?.takeIf { it.isNotBlank() },
            depth = 64,
            enabled = true,
            networkPolicy = networkPolicy,
        )

        val updated = uiState.value.syncProfiles + profile
        IronmeshPreferences.setFolderSyncConfigs(getApplication(), updated)
        uiState.value = uiState.value.copy(
            syncProfiles = updated,
            newSyncLabel = "",
            newSyncPrefix = "",
            newSyncLocalFolder = "",
            newSyncLocalFolderTreeUri = null,
            newSyncAllowWifi = true,
            newSyncAllowCellular = true,
            newSyncAllowOtherConnections = true,
            newSyncAllowRoaming = false,
            newSyncAllowedWifiSsids = "",
            status = "Added sync profile '${profile.label}'",
        )

        FolderSyncScheduler.reschedule(getApplication())
        FolderSyncScheduler.runNow(getApplication())
        return profile.networkPolicy
    }

    fun setFolderSyncProfileEnabled(profileId: String, enabled: Boolean) {
        val updated = uiState.value.syncProfiles.map { profile ->
            if (profile.id == profileId) profile.copy(enabled = enabled) else profile
        }
        IronmeshPreferences.setFolderSyncConfigs(getApplication(), updated)
        uiState.value = uiState.value.copy(syncProfiles = updated)
        FolderSyncScheduler.reschedule(getApplication())
    }

    fun removeFolderSyncProfile(profileId: String) {
        val updated = uiState.value.syncProfiles.filterNot { it.id == profileId }
        IronmeshPreferences.setFolderSyncConfigs(getApplication(), updated)
        val updatedHistory = uiState.value.folderSyncHistory.toMutableMap().apply {
            remove(profileId)
        }
        uiState.value = uiState.value.copy(
            syncProfiles = updated,
            folderSyncHistory = updatedHistory,
            status = "Removed sync profile",
        )
        FolderSyncScheduler.reschedule(getApplication())
    }

    fun updateFolderSyncProfileNetworkPolicy(
        profileId: String,
        networkPolicy: FolderSyncNetworkPolicy,
    ): Boolean {
        val normalizedPolicy = networkPolicy.normalized()
        if (!normalizedPolicy.hasAnyAllowedTransport()) {
            setStatus("Error: Select at least one allowed network type")
            return false
        }

        val targetProfile = uiState.value.syncProfiles.firstOrNull { profile -> profile.id == profileId }
            ?: return false
        val updated = uiState.value.syncProfiles.map { profile ->
            if (profile.id == profileId) {
                profile.copy(networkPolicy = normalizedPolicy)
            } else {
                profile
            }
        }
        IronmeshPreferences.setFolderSyncConfigs(getApplication(), updated)
        uiState.value = uiState.value.copy(
            syncProfiles = updated,
            status = "Updated network rules for '${targetProfile.label}'",
        )
        FolderSyncScheduler.reschedule(getApplication())
        return true
    }

    fun runFolderSyncNow() {
        val status = uiState.value.folderSyncStatus
        val continuousSyncActive = status.activeProfileCount > 0L &&
            status.serviceState in setOf("starting", "running", "syncing")
        if (continuousSyncActive) {
            refreshExpandedFolderSyncHistory(force = true)
            setStatus("Continuous folder sync already active; manual one-shot run skipped")
            return
        }

        val enabledProfiles = uiState.value.syncProfiles.filter { profile -> profile.enabled }
        if (enabledProfiles.isEmpty()) {
            setStatus("No enabled sync profile is configured")
            return
        }
        val eligibleProfiles = FolderSyncNetworkGate
            .evaluateProfiles(getApplication(), enabledProfiles)
        val firstBlocked = eligibleProfiles.firstOrNull { evaluation -> !evaluation.decision.allowed }
        if (eligibleProfiles.none { evaluation -> evaluation.decision.allowed }) {
            val reason = firstBlocked?.decision?.reason ?: "No profile is allowed on the current network"
            setStatus("Sync skipped: $reason")
            return
        }

        FolderSyncScheduler.runNow(getApplication())
        setStatus("Folder sync scheduled")
    }

    fun retryFolderSyncConnection() {
        val enabledProfiles = uiState.value.syncProfiles.filter { profile -> profile.enabled }
        if (enabledProfiles.isEmpty()) {
            setStatus("No enabled sync profile is configured")
            return
        }
        FolderSyncForegroundService.retryNow(getApplication())
        setStatus("Requested a sync connection retry")
    }

    fun toggleFolderSyncHistory(profileId: String) {
        val current = uiState.value.folderSyncHistory[profileId] ?: FolderSyncHistoryState()
        updateFolderSyncHistoryState(profileId) { historyState ->
            historyState.copy(
                expanded = !current.expanded,
                error = if (current.expanded) null else historyState.error,
            )
        }
        val next = uiState.value.folderSyncHistory[profileId] ?: FolderSyncHistoryState()
        if (next.expanded && (next.records.isEmpty() || isHistoryStale(next))) {
            refreshFolderSyncHistory(profileId)
        }
    }

    fun setFolderSyncHistoryFilter(
        profileId: String,
        filter: FolderSyncActivityFilter,
    ) {
        updateFolderSyncHistoryState(profileId) { historyState ->
            historyState.copy(filter = filter)
        }
    }

    fun loadMoreFolderSyncHistory(profileId: String) {
        val current = uiState.value.folderSyncHistory[profileId] ?: return
        if (current.loading || current.nextBeforeId == null) {
            return
        }
        refreshFolderSyncHistory(
            profileId = profileId,
            beforeId = current.nextBeforeId,
            append = true,
        )
    }

    fun startWebUi() {
        val deviceAuth = try {
            currentDeviceAuthState()
        } catch (error: DeviceIdentityStorageException) {
            uiState.value = uiState.value.copy(
                webUiSession = null,
                status = "Device identity unavailable: ${error.message}",
            )
            return
        }
        val connectionInput = deviceAuth.preferredConnectionInput()
        val clientIdentityJson = deviceAuth.toClientIdentityJson()
        if (connectionInput.isBlank() || clientIdentityJson.isNullOrBlank()) {
            uiState.value = uiState.value.copy(
                webUiSession = null,
                status = "Enroll this device before opening the Web UI.",
            )
            return
        }
        uiState.value = uiState.value.copy(
            loading = true,
            webUiSession = null,
            status = "Starting Web UI...",
        )
        viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    repository.startWebUi(
                        connectionInput,
                        deviceAuth.serverCaPem?.takeIf { it.isNotBlank() },
                        clientIdentityJson,
                    )
                }
            }
            runCatching { refreshPersistedDeviceAuthState() }
                .onFailure { error ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        status = "Device identity unavailable: ${error.message}",
                    )
                    return@launch
                }
            result
                .onSuccess { session ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        webUiSession = session,
                        status = "Web UI ready.",
                    )
                }
                .onFailure { error ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        status = "Error: ${error.message}",
                    )
                }
        }
    }

    fun enrollDevice() {
        val bootstrapJson = uiState.value.bootstrapInput.trim()
        if (bootstrapJson.isBlank()) {
            val detail = "Bootstrap claim or bundle is required"
            uiState.value = uiState.value.copy(
                status = "Error: $detail",
                enrollmentDiagnostics = newEnrollmentDiagnostics().withEnrollmentDiagnosticStatus(
                    stepId = EnrollmentDiagnosticStepId.BOOTSTRAP,
                    status = EnrollmentDiagnosticStepStatus.FAILED,
                    detail = detail,
                ),
            )
            return
        }

        val label = uiState.value.deviceLabelInput.trim().takeIf { it.isNotBlank() }
        val existingDeviceId = uiState.value.deviceAuthState.deviceId.takeIf { it.isNotBlank() }
        uiState.value = uiState.value.copy(
            loading = true,
            status = "Enrolling device...",
            enrollmentDiagnostics = newEnrollmentDiagnostics().withEnrollmentDiagnosticStatus(
                stepId = EnrollmentDiagnosticStepId.BOOTSTRAP,
                status = EnrollmentDiagnosticStepStatus.IN_PROGRESS,
            ),
        )
        viewModelScope.launch {
            val authState = try {
                withContext(Dispatchers.IO) {
                    repository.enrollWithBootstrap(
                        bootstrapJson = bootstrapJson,
                        deviceId = existingDeviceId,
                        label = label,
                    )
                }
            } catch (error: Throwable) {
                finishEnrollmentWithError(EnrollmentDiagnosticStepId.BOOTSTRAP, error)
                return@launch
            }

            uiState.value = uiState.value.copy(
                status = "Verifying enrollment...",
                enrollmentDiagnostics = uiState.value.enrollmentDiagnostics
                    .withEnrollmentDiagnosticStatus(
                        stepId = EnrollmentDiagnosticStepId.BOOTSTRAP,
                        status = EnrollmentDiagnosticStepStatus.SUCCEEDED,
                    )
                    .withEnrollmentDiagnosticStatus(
                        stepId = EnrollmentDiagnosticStepId.VERIFY_ACCESS,
                        status = EnrollmentDiagnosticStepStatus.IN_PROGRESS,
                        detail = enrollmentVerificationProgressDetail(
                            elapsedMs = 0L,
                            connectionRoutes = null,
                        ),
                    ),
            )
            val verificationStartedAtNanos = System.nanoTime()
            startEnrollmentVerificationMonitor(authState, verificationStartedAtNanos)
            Log.i(ENROLLMENT_LOG_TAG, "signed access verification started")
            val verification: EnrollmentAccessVerification
            try {
                verification = withContext(Dispatchers.IO) {
                    repository.verifyEnrollmentAccess(authState)
                }
            } catch (error: Throwable) {
                finishEnrollmentWithError(EnrollmentDiagnosticStepId.VERIFY_ACCESS, error)
                return@launch
            }
            stopEnrollmentVerificationMonitor()
            Log.i(
                ENROLLMENT_LOG_TAG,
                enrollmentVerificationSuccessDetail(verification),
            )

            uiState.value = uiState.value.copy(
                status = "Saving device identity...",
                enrollmentDiagnostics = uiState.value.enrollmentDiagnostics
                    .withEnrollmentDiagnosticStatus(
                        stepId = EnrollmentDiagnosticStepId.VERIFY_ACCESS,
                        status = EnrollmentDiagnosticStepStatus.SUCCEEDED,
                        detail = enrollmentVerificationSuccessDetail(verification),
                    )
                    .withEnrollmentDiagnosticStatus(
                        stepId = EnrollmentDiagnosticStepId.SAVE_IDENTITY,
                        status = EnrollmentDiagnosticStepStatus.IN_PROGRESS,
                    ),
            )
            try {
                withContext(Dispatchers.IO) {
                    repository.stopWebUi()
                    IronmeshPreferences.setDeviceAuthState(getApplication(), authState)
                }
            } catch (error: Throwable) {
                finishEnrollmentWithError(EnrollmentDiagnosticStepId.SAVE_IDENTITY, error)
                return@launch
            }

            stopConnectionRoutesMonitor()
            uiState.value = uiState.value.copy(
                loading = false,
                deviceAuthState = authState,
                bootstrapInput = "",
                deviceLabelInput = authState.label.orEmpty(),
                enrollmentDiagnostics = uiState.value.enrollmentDiagnostics
                    .withEnrollmentDiagnosticStatus(
                        stepId = EnrollmentDiagnosticStepId.SAVE_IDENTITY,
                        status = EnrollmentDiagnosticStepStatus.SUCCEEDED,
                    ),
                connectionRoutes = null,
                connectionRoutesError = null,
                connectionRoutesLastLoadedUnixMs = 0L,
                selectedSection = MainSection.HOME,
                webUiSession = null,
                status = "Device enrolled: ${authState.deviceId}",
            )
            FolderSyncScheduler.reschedule(getApplication())
        }
    }

    private fun finishEnrollmentWithError(
        stepId: EnrollmentDiagnosticStepId,
        error: Throwable,
    ) {
        stopEnrollmentVerificationMonitor()
        val detail = enrollmentDiagnosticErrorDetail(error)
        if (stepId == EnrollmentDiagnosticStepId.VERIFY_ACCESS) {
            Log.e(ENROLLMENT_LOG_TAG, detail, error)
        }
        uiState.value = uiState.value.copy(
            loading = false,
            status = "Error: $detail",
            enrollmentDiagnostics = uiState.value.enrollmentDiagnostics.withEnrollmentDiagnosticStatus(
                stepId = stepId,
                status = EnrollmentDiagnosticStepStatus.FAILED,
                detail = detail,
            ),
        )
    }

    private fun execute(loadingMessage: String, action: suspend () -> String) {
        uiState.value = uiState.value.copy(loading = true, status = loadingMessage)
        viewModelScope.launch {
            val result = runCatching { action() }
            runCatching { refreshPersistedDeviceAuthState() }
                .onFailure { error ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        status = "Device identity unavailable: ${error.message}",
                    )
                    return@launch
                }
            result
                .onSuccess { message ->
                    uiState.value = uiState.value.copy(loading = false, status = message)
                }
                .onFailure { error ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        status = "Error: ${error.message}",
                    )
                }
        }
    }

    private fun observeFolderSyncStatus() {
        viewModelScope.launch {
            var historyRefreshTick = 0
            while (isActive) {
                val status = withContext(Dispatchers.IO) {
                    runCatching { repository.getContinuousFolderSyncStatus() }
                        .getOrDefault(FolderSyncServiceStatus())
                }
                val connectionStatus = IronmeshPreferences.getAppConnectionStatus(getApplication())
                uiState.value = uiState.value.copy(
                    folderSyncStatus = status,
                    appConnectionStatus = connectionStatus,
                )
                historyRefreshTick += 1
                if (historyRefreshTick >= 5) {
                    historyRefreshTick = 0
                    refreshExpandedFolderSyncHistory()
                }
                delay(1_000)
            }
        }
    }

    private fun refreshExpandedFolderSyncHistory(force: Boolean = false) {
        if (uiState.value.selectedSection != MainSection.SYNC) {
            return
        }
        val historyStates = uiState.value.folderSyncHistory
        historyStates.forEach { (profileId, historyState) ->
            if (!historyState.expanded || historyState.loading) {
                return@forEach
            }
            if (force || isHistoryStale(historyState)) {
                refreshFolderSyncHistory(profileId)
            }
        }
    }

    private fun refreshFolderSyncHistory(
        profileId: String,
        beforeId: Long? = null,
        append: Boolean = false,
    ) {
        val profile = uiState.value.syncProfiles.firstOrNull { it.id == profileId } ?: return
        val existing = uiState.value.folderSyncHistory[profileId] ?: FolderSyncHistoryState()
        if (existing.loading) {
            return
        }

        val limit = if (append) {
            FOLDER_SYNC_HISTORY_PAGE_SIZE
        } else {
            existing.records.size.coerceAtLeast(FOLDER_SYNC_HISTORY_PAGE_SIZE)
        }
        val connectionInput = runCatching { currentConnectionInput() }
            .getOrElse { error ->
                updateFolderSyncHistoryState(profileId) { historyState ->
                    historyState.copy(
                        expanded = true,
                        loading = false,
                        error = error.message ?: "Device identity is unavailable",
                    )
                }
                uiState.value = uiState.value.copy(
                    status = "Device identity unavailable: ${error.message}",
                )
                return
            }
        updateFolderSyncHistoryState(profileId) { historyState ->
            historyState.copy(
                expanded = true,
                loading = true,
                error = null,
            )
        }

        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    repository.getFolderSyncModificationHistory(
                        connectionInput = connectionInput,
                        profile = profile,
                        limit = limit,
                        beforeId = beforeId,
                    )
                }
            }
                .onSuccess { history ->
                    updateFolderSyncHistoryState(profileId) { historyState ->
                        val nextRecords = if (append) {
                            (historyState.records + history.records).distinctBy { record -> record.id }
                        } else {
                            history.records
                        }
                        historyState.copy(
                            expanded = true,
                            records = nextRecords,
                            nextBeforeId = history.nextBeforeId,
                            loading = false,
                            error = null,
                            lastLoadedUnixMs = System.currentTimeMillis(),
                        )
                    }
                }
                .onFailure { error ->
                    updateFolderSyncHistoryState(profileId) { historyState ->
                        historyState.copy(
                            expanded = true,
                            loading = false,
                            error = error.message ?: "Failed to load recent activity",
                        )
                    }
                }
        }
    }

    private fun updateFolderSyncHistoryState(
        profileId: String,
        transform: (FolderSyncHistoryState) -> FolderSyncHistoryState,
    ) {
        val current = uiState.value.folderSyncHistory[profileId] ?: FolderSyncHistoryState()
        val updated = uiState.value.folderSyncHistory.toMutableMap().apply {
            put(profileId, transform(current))
        }
        uiState.value = uiState.value.copy(folderSyncHistory = updated)
    }

    private fun isHistoryStale(historyState: FolderSyncHistoryState): Boolean {
        return System.currentTimeMillis() - historyState.lastLoadedUnixMs >=
            FOLDER_SYNC_HISTORY_REFRESH_MS
    }

    private data class GalleryRequest(
        val mode: GalleryViewMode,
        val currentDirectoryDocumentId: String,
        val currentDirectoryPath: String,
        val breadcrumbs: List<GalleryBreadcrumbItem>,
        val sort: GallerySortOption,
        val pageSize: Int,
    )

    private data class GalleryLoadSnapshot(
        val mode: GalleryViewMode,
        val currentDirectoryDocumentId: String,
        val currentDirectoryPath: String,
        val breadcrumbs: List<GalleryBreadcrumbItem>,
        val directories: List<GalleryDirectoryItem>,
        val collection: GalleryCollectionState,
        val firstPageItems: List<GalleryImageItem>,
    )

    private fun currentGalleryRequest(pageSize: Int): GalleryRequest {
        val current = uiState.value
        return GalleryRequest(
            mode = current.galleryMode,
            currentDirectoryDocumentId = current.galleryCurrentDirectoryDocumentId,
            currentDirectoryPath = current.galleryCurrentDirectoryPath,
            breadcrumbs = current.galleryBreadcrumbs,
            sort = current.gallerySort,
            pageSize = pageSize.coerceAtLeast(1),
        )
    }

    private suspend fun loadGalleryState(request: GalleryRequest): GalleryLoadSnapshot {
        return when (request.mode) {
            GalleryViewMode.FLATTENED_ALL_IMAGES -> loadFlattenedGalleryState(request)
            GalleryViewMode.CURRENT_DIRECTORY -> loadCurrentDirectoryGalleryState(request)
        }
    }

    private suspend fun loadFlattenedGalleryState(request: GalleryRequest): GalleryLoadSnapshot {
        val firstPage = repository.storeIndexImagePage(
            connectionInput = currentConnectionInput(),
            prefix = null,
            depth = GALLERY_FLATTENED_DEPTH,
            offset = 0,
            limit = request.pageSize,
            sort = resolveGalleryStoreSortOrder(request.sort),
            serverCaPem = currentServerCaPem(),
            clientIdentityJson = currentClientIdentityJson(),
        )
        val items = firstPage.entries.mapNotNull(::galleryImageItemFromEntry)
        val totalItemCount = firstPage.total_entry_count.coerceAtLeast(items.size)
        return GalleryLoadSnapshot(
            mode = GalleryViewMode.FLATTENED_ALL_IMAGES,
            currentDirectoryDocumentId = GALLERY_ROOT_DOCUMENT_ID,
            currentDirectoryPath = GALLERY_ROOT_PATH,
            breadcrumbs = emptyList(),
            directories = emptyList(),
            collection = GalleryCollectionState(
                totalItemCount = totalItemCount,
                pageSize = request.pageSize,
                pageCount = resolveGalleryPageCount(totalItemCount, request.pageSize),
            ),
            firstPageItems = items,
        )
    }

    private suspend fun loadCurrentDirectoryGalleryState(request: GalleryRequest): GalleryLoadSnapshot {
        val prefix = galleryPrefixForPath(request.currentDirectoryPath)
        val listing = repository.storeIndexDirectoryListing(
            connectionInput = currentConnectionInput(),
            prefix = prefix,
            depth = 1,
            serverCaPem = currentServerCaPem(),
            clientIdentityJson = currentClientIdentityJson(),
        )
        val firstPage = repository.storeIndexImagePage(
            connectionInput = currentConnectionInput(),
            prefix = prefix,
            depth = 1,
            offset = 0,
            limit = request.pageSize,
            sort = resolveGalleryStoreSortOrder(request.sort),
            serverCaPem = currentServerCaPem(),
            clientIdentityJson = currentClientIdentityJson(),
        )
        val directories = listing.entries.mapNotNull(::galleryDirectoryItemFromEntry)
        val items = firstPage.entries.mapNotNull(::galleryImageItemFromEntry)
        val totalItemCount = firstPage.total_entry_count.coerceAtLeast(items.size)

        return GalleryLoadSnapshot(
            mode = GalleryViewMode.CURRENT_DIRECTORY,
            currentDirectoryDocumentId = request.currentDirectoryDocumentId,
            currentDirectoryPath = request.currentDirectoryPath,
            breadcrumbs = request.breadcrumbs,
            directories = directories,
            collection = GalleryCollectionState(
                totalItemCount = totalItemCount,
                pageSize = request.pageSize,
                pageCount = resolveGalleryPageCount(totalItemCount, request.pageSize),
            ),
            firstPageItems = items,
        )
    }

    private suspend fun loadGalleryPage(
        request: GalleryRequest,
        pageIndex: Int,
    ): StoreIndexResponse {
        val pageSize = request.pageSize.coerceAtLeast(1)
        val offset = pageIndex.coerceAtLeast(0) * pageSize
        return repository.storeIndexImagePage(
            connectionInput = currentConnectionInput(),
            prefix = when (request.mode) {
                GalleryViewMode.FLATTENED_ALL_IMAGES -> null
                GalleryViewMode.CURRENT_DIRECTORY -> galleryPrefixForPath(request.currentDirectoryPath)
            },
            depth = when (request.mode) {
                GalleryViewMode.FLATTENED_ALL_IMAGES -> GALLERY_FLATTENED_DEPTH
                GalleryViewMode.CURRENT_DIRECTORY -> 1
            },
            offset = offset,
            limit = pageSize,
            sort = resolveGalleryStoreSortOrder(request.sort),
            serverCaPem = currentServerCaPem(),
            clientIdentityJson = currentClientIdentityJson(),
        )
    }

    private fun refreshPersistedDeviceAuthState(): DeviceAuthState {
        val persisted = IronmeshPreferences.getDeviceAuthState(getApplication())
        if (persisted != uiState.value.deviceAuthState) {
            uiState.value = uiState.value.copy(deviceAuthState = persisted)
        }
        return persisted
    }

    private fun currentDeviceAuthState(): DeviceAuthState {
        return refreshPersistedDeviceAuthState()
    }

    private fun currentClientIdentityJson(): String? {
        return currentDeviceAuthState().toClientIdentityJson()
    }

    private fun currentConnectionInput(): String {
        return currentDeviceAuthState().preferredConnectionInput()
    }

    private fun currentServerCaPem(): String? {
        return currentDeviceAuthState().serverCaPem?.takeIf { it.isNotBlank() }
    }

    private fun startConnectionRoutesMonitor() {
        if (connectionRoutesMonitorJob?.isActive == true) {
            return
        }
        connectionRoutesMonitorJob = viewModelScope.launch {
            loadConnectionRoutes(
                refresh = false,
                showLoading = uiState.value.connectionRoutes == null,
                statusOnFailure = false,
            )
            while (isActive) {
                delay(CONNECTION_ROUTE_SNAPSHOT_POLL_MS)
                if (uiState.value.connectionRoutesLoading) {
                    continue
                }
                loadConnectionRoutes(
                    refresh = false,
                    showLoading = false,
                    statusOnFailure = false,
                )
            }
        }
    }

    private fun stopConnectionRoutesMonitor() {
        connectionRoutesMonitorJob?.cancel()
        connectionRoutesMonitorJob = null
    }

    private fun startEnrollmentVerificationMonitor(
        authState: DeviceAuthState,
        startedAtNanos: Long,
    ) {
        stopEnrollmentVerificationMonitor()
        enrollmentVerificationMonitorJob = viewModelScope.launch {
            while (isActive) {
                delay(ENROLLMENT_VERIFICATION_POLL_MS)
                val routes = withContext(Dispatchers.IO) {
                    runCatching {
                        repository.getConnectionRouteSnapshot(
                            connectionInput = authState.preferredConnectionInput(),
                            serverCaPem = authState.serverCaPem?.takeIf { it.isNotBlank() },
                            clientIdentityJson = authState.toClientIdentityJson(),
                            refresh = false,
                        )
                    }.getOrNull()
                }
                val detail = enrollmentVerificationProgressDetail(
                    elapsedMs = elapsedMillisSince(startedAtNanos),
                    connectionRoutes = routes,
                )
                val diagnostic = uiState.value.enrollmentDiagnostics
                    .firstOrNull { it.id == EnrollmentDiagnosticStepId.VERIFY_ACCESS }
                if (diagnostic?.status != EnrollmentDiagnosticStepStatus.IN_PROGRESS) {
                    return@launch
                }
                uiState.value = uiState.value.copy(
                    enrollmentDiagnostics = uiState.value.enrollmentDiagnostics
                        .withEnrollmentDiagnosticStatus(
                            stepId = EnrollmentDiagnosticStepId.VERIFY_ACCESS,
                            status = EnrollmentDiagnosticStepStatus.IN_PROGRESS,
                            detail = detail,
                        ),
                )
                Log.i(ENROLLMENT_LOG_TAG, detail)
            }
        }
    }

    private fun stopEnrollmentVerificationMonitor() {
        enrollmentVerificationMonitorJob?.cancel()
        enrollmentVerificationMonitorJob = null
    }

    private fun elapsedMillisSince(startedAtNanos: Long): Long {
        return ((System.nanoTime() - startedAtNanos) / 1_000_000L).coerceAtLeast(0L)
    }

    private suspend fun loadConnectionRoutes(
        refresh: Boolean,
        showLoading: Boolean,
        statusOnFailure: Boolean,
    ) {
        val deviceAuth = try {
            currentDeviceAuthState()
        } catch (error: DeviceIdentityStorageException) {
            uiState.value = uiState.value.copy(
                connectionRoutesLoading = false,
                connectionRoutesError = error.message,
                status = if (statusOnFailure) {
                    "Device identity unavailable: ${error.message}"
                } else {
                    uiState.value.status
                },
            )
            return
        }
        val connectionInput = deviceAuth.preferredConnectionInput()
        val clientIdentityJson = deviceAuth.toClientIdentityJson()
        if (connectionInput.isBlank() || clientIdentityJson.isNullOrBlank()) {
            uiState.value = uiState.value.copy(
                connectionRoutesLoading = false,
                connectionRoutesError = "Enroll this device to inspect connection paths.",
            )
            return
        }

        if (showLoading) {
            uiState.value = uiState.value.copy(
                connectionRoutesLoading = true,
                connectionRoutesError = null,
            )
        }

        runCatching {
            withContext(Dispatchers.IO) {
                repository.getConnectionRouteSnapshot(
                    connectionInput = connectionInput,
                    serverCaPem = deviceAuth.serverCaPem?.takeIf { it.isNotBlank() },
                    clientIdentityJson = clientIdentityJson,
                    refresh = refresh,
                )
            }
        }
            .onSuccess { snapshot ->
                uiState.value = uiState.value.copy(
                    connectionRoutes = snapshot,
                    connectionRoutesLoading = false,
                    connectionRoutesError = null,
                    connectionRoutesLastLoadedUnixMs = System.currentTimeMillis(),
                )
            }
            .onFailure { error ->
                uiState.value = uiState.value.copy(
                    connectionRoutesLoading = false,
                    connectionRoutesError = error.message ?: "Failed to load connection paths",
                    status = if (statusOnFailure) {
                        "Error: ${error.message}"
                    } else {
                        uiState.value.status
                    },
                )
            }
    }

    private fun galleryImageItemFromEntry(entry: StoreIndexEntry): GalleryImageItem? {
        if (entry.entry_type != "key") {
            return null
        }
        val path = entry.path.trim().trim('/')
        if (path.isBlank()) {
            return null
        }
        val application = getApplication<Application>()
        val authority = "${application.packageName}.documents"
        return GalleryImageItem(
            documentUri = DocumentsContract.buildDocumentUri(authority, galleryFileDocumentId(path)),
            displayName = path.substringAfterLast('/'),
            remotePath = path,
            mimeType = entry.media?.mime_type ?: "image/*",
            createdAtUnixMs = entry.media?.taken_at_unix?.times(1000),
            width = entry.media?.width,
            height = entry.media?.height,
            thumbnailStatus = entry.media?.status,
        )
    }

    private fun galleryDirectoryItemFromEntry(entry: StoreIndexEntry): GalleryDirectoryItem? {
        if (entry.entry_type != "prefix") {
            return null
        }
        val normalizedPath = entry.path.trim().trim('/').removeSuffix("/")
        if (normalizedPath.isBlank()) {
            return null
        }
        return GalleryDirectoryItem(
            documentId = galleryDirectoryDocumentId(normalizedPath),
            displayName = normalizedPath.substringAfterLast('/'),
            pathLabel = normalizeGalleryDirectoryPath(normalizedPath),
        )
    }

    private fun resolveGalleryStoreSortOrder(sort: GallerySortOption): StoreIndexSortOrder {
        return when (sort) {
            GallerySortOption.CREATION_TIME -> StoreIndexSortOrder.CAPTURED_DESC
            GallerySortOption.NAME -> StoreIndexSortOrder.PATH_ASC
        }
    }

    private fun resolveGalleryPageCount(
        totalItemCount: Int,
        pageSize: Int,
    ): Int {
        if (totalItemCount <= 0) {
            return 0
        }
        return (totalItemCount + pageSize.coerceAtLeast(1) - 1) / pageSize.coerceAtLeast(1)
    }

    private fun galleryPrefixForPath(path: String): String? {
        val normalized = path.trim().trim('/')
        return normalized.takeIf { it.isNotBlank() }
    }

    private fun galleryDirectoryDocumentId(path: String): String {
        return if (path.isBlank()) GALLERY_ROOT_DOCUMENT_ID else "dir:${path.trim('/')}"
    }

    private fun galleryFileDocumentId(path: String): String = "file:${path.trim('/')}"

    private fun pageIndexForGalleryEntry(
        index: Int,
        pageSize: Int,
    ): Int {
        return index / pageSize.coerceAtLeast(1)
    }

    private fun galleryEntryWithinPage(
        index: Int,
        pageSize: Int,
    ): Int {
        return index % pageSize.coerceAtLeast(1)
    }

    private fun nextGalleryRequestVersion(): Int {
        galleryRequestVersion += 1
        return galleryRequestVersion
    }

    private fun isCurrentGalleryRequest(requestVersion: Int): Boolean {
        return requestVersion == galleryRequestVersion
    }

    private fun normalizeGalleryDirectoryPath(path: String): String {
        val normalized = path.trim().trim('/')
        return if (normalized.isBlank()) GALLERY_ROOT_PATH else "$normalized/"
    }
}
