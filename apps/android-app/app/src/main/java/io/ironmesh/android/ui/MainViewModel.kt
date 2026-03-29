package io.ironmesh.android.ui

import android.app.Application
import android.net.Uri
import android.provider.DocumentsContract
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.ironmesh.android.data.DeviceAuthState
import io.ironmesh.android.data.FolderSyncConfig
import io.ironmesh.android.data.FolderSyncServiceStatus
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import io.ironmesh.android.saf.IronmeshDocumentColumns
import io.ironmesh.android.work.FolderSyncScheduler
import kotlinx.coroutines.Dispatchers
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
    SETTINGS,
    WEB_UI,
    GALLERY,
}

private const val GALLERY_ROOT_DOCUMENT_ID = "dir:"
private const val GALLERY_ROOT_PATH = "/"

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

data class MainUiState(
    val baseUrl: String = IronmeshPreferences.DEFAULT_BASE_URL,
    val deviceAuthState: DeviceAuthState = DeviceAuthState(),
    val bootstrapInput: String = "",
    val deviceLabelInput: String = "",
    val key: String = "demo-key",
    val payload: String = "hello from android",
    val status: String = "Ready",
    val objectBody: String = "",
    val syncProfiles: List<FolderSyncConfig> = emptyList(),
    val folderSyncStatus: FolderSyncServiceStatus = FolderSyncServiceStatus(),
    val newSyncLabel: String = "",
    val newSyncPrefix: String = "",
    val newSyncLocalFolder: String = "",
    val newSyncLocalFolderTreeUri: String? = null,
    val selectedSection: MainSection = MainSection.SETTINGS,
    val webUiUrl: String = "",
    val galleryMode: GalleryViewMode = GalleryViewMode.FLATTENED_ALL_IMAGES,
    val galleryItems: List<GalleryImageItem> = emptyList(),
    val galleryDirectories: List<GalleryDirectoryItem> = emptyList(),
    val galleryBreadcrumbs: List<GalleryBreadcrumbItem> = emptyList(),
    val galleryCurrentDirectoryDocumentId: String = GALLERY_ROOT_DOCUMENT_ID,
    val galleryCurrentDirectoryPath: String = GALLERY_ROOT_PATH,
    val gallerySort: GallerySortOption = GallerySortOption.CREATION_TIME,
    val galleryLoading: Boolean = false,
    val loading: Boolean = false,
)

class MainViewModel(
    application: Application,
) : AndroidViewModel(application) {

    private val repository = IronmeshRepository()

    var uiState = androidx.compose.runtime.mutableStateOf(MainUiState())
        private set

    init {
        val persistedBaseUrl = IronmeshPreferences.getBaseUrl(getApplication())
        val persistedProfiles = IronmeshPreferences.getFolderSyncConfigs(getApplication())
        val persistedDeviceAuth = IronmeshPreferences.getDeviceAuthState(getApplication())
        val persistedGalleryViewMode = IronmeshPreferences.getGalleryViewMode(getApplication())
        uiState.value = uiState.value.copy(
            baseUrl = persistedBaseUrl,
            syncProfiles = persistedProfiles,
            deviceAuthState = persistedDeviceAuth,
            deviceLabelInput = persistedDeviceAuth.label.orEmpty(),
            galleryMode = persistedGalleryViewMode,
        )
        FolderSyncScheduler.reschedule(getApplication())
        observeFolderSyncStatus()
    }

    fun updateBaseUrl(value: String) {
        uiState.value = uiState.value.copy(baseUrl = value)
        IronmeshPreferences.setBaseUrl(getApplication(), value)
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

    fun selectSection(section: MainSection) {
        uiState.value = uiState.value.copy(selectedSection = section)
    }

    fun refreshGallery() {
        uiState.value = uiState.value.copy(galleryLoading = true, status = "Loading gallery...")
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    loadGalleryState()
                }
            }
                .onSuccess { snapshot ->
                    val sorted = sortGallery(snapshot.images, uiState.value.gallerySort)
                    uiState.value = uiState.value.copy(
                        galleryDirectories = snapshot.directories,
                        galleryBreadcrumbs = snapshot.breadcrumbs,
                        galleryCurrentDirectoryDocumentId = snapshot.currentDirectoryDocumentId,
                        galleryCurrentDirectoryPath = snapshot.currentDirectoryPath,
                        galleryItems = sorted,
                        galleryLoading = false,
                        status = when (snapshot.mode) {
                            GalleryViewMode.FLATTENED_ALL_IMAGES ->
                                "Gallery loaded: ${sorted.size} images"
                            GalleryViewMode.CURRENT_DIRECTORY ->
                                "Gallery loaded: ${sorted.size} images, ${snapshot.directories.size} folders in ${snapshot.currentDirectoryPath}"
                        },
                    )
                }
                .onFailure { error ->
                    uiState.value = uiState.value.copy(
                        galleryLoading = false,
                        status = "Error: ${error.message}",
                    )
                }
        }
    }

    fun updateGallerySort(sort: GallerySortOption) {
        uiState.value = uiState.value.copy(
            gallerySort = sort,
            galleryItems = sortGallery(uiState.value.galleryItems, sort),
        )
    }

    fun updateGalleryViewMode(mode: GalleryViewMode) {
        if (uiState.value.galleryMode == mode) {
            return
        }
        IronmeshPreferences.setGalleryViewMode(getApplication(), mode)
        uiState.value = uiState.value.copy(
            galleryMode = mode,
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
            galleryBreadcrumbs = nextBreadcrumbs,
            galleryCurrentDirectoryDocumentId = nextCurrent?.documentId ?: GALLERY_ROOT_DOCUMENT_ID,
            galleryCurrentDirectoryPath = nextCurrent?.pathLabel ?: GALLERY_ROOT_PATH,
        )
        refreshGallery()
    }

    fun addFolderSyncProfile() {
        val localFolder = uiState.value.newSyncLocalFolder.trim()
        if (localFolder.isBlank()) {
            setStatus("Error: Local folder path is required")
            return
        }

        val prefix = uiState.value.newSyncPrefix.trim().trim('/').replace('\\', '/')
        val label = uiState.value.newSyncLabel.trim().ifBlank {
            localFolder.substringAfterLast('/').ifBlank { "Sync Profile" }
        }

        val profile = FolderSyncConfig(
            id = UUID.randomUUID().toString(),
            label = label,
            prefix = prefix,
            localFolder = localFolder,
            localFolderTreeUri = uiState.value.newSyncLocalFolderTreeUri?.takeIf { it.isNotBlank() },
            depth = 64,
            enabled = true,
        )

        val updated = uiState.value.syncProfiles + profile
        IronmeshPreferences.setFolderSyncConfigs(getApplication(), updated)
        uiState.value = uiState.value.copy(
            syncProfiles = updated,
            newSyncLabel = "",
            newSyncPrefix = "",
            newSyncLocalFolder = "",
            newSyncLocalFolderTreeUri = null,
            status = "Added sync profile '${profile.label}'",
        )

        FolderSyncScheduler.reschedule(getApplication())
        FolderSyncScheduler.runNow(getApplication())
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
        uiState.value = uiState.value.copy(
            syncProfiles = updated,
            status = "Removed sync profile",
        )
        FolderSyncScheduler.reschedule(getApplication())
    }

    fun runFolderSyncNow() {
        FolderSyncScheduler.runNow(getApplication())
        setStatus("Folder sync scheduled")
    }

    fun startWebUi() {
        val connectionInput = currentConnectionInput()
        val clientIdentityJson = currentClientIdentityJson()
        uiState.value = uiState.value.copy(
            loading = true,
            selectedSection = MainSection.WEB_UI,
            webUiUrl = "",
            status = "Starting Web UI...",
        )
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    repository.startWebUi(
                        connectionInput,
                        currentServerCaPem(),
                        clientIdentityJson,
                    )
                }
            }
                .onSuccess { url ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        webUiUrl = url,
                        status = "Web UI ready at $url",
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
            setStatus("Error: Bootstrap claim or bundle is required")
            return
        }

        val label = uiState.value.deviceLabelInput.trim().takeIf { it.isNotBlank() }
        uiState.value = uiState.value.copy(loading = true, status = "Enrolling device...")
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    repository.enrollWithBootstrap(
                        bootstrapJson = bootstrapJson,
                        deviceId = uiState.value.deviceAuthState.deviceId.takeIf { it.isNotBlank() },
                        label = label,
                    )
                }
            }
                .onSuccess { authState ->
                    IronmeshPreferences.setDeviceAuthState(getApplication(), authState)
                    uiState.value = uiState.value.copy(
                        loading = false,
                        deviceAuthState = authState,
                        bootstrapInput = "",
                        deviceLabelInput = authState.label.orEmpty(),
                        status = "Device enrolled: ${authState.deviceId}",
                    )
                    FolderSyncScheduler.reschedule(getApplication())
                }
                .onFailure { error ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        status = "Error: ${error.message}",
                    )
                }
        }
    }

    fun clearDeviceEnrollment() {
        IronmeshPreferences.clearDeviceAuthState(getApplication())
        uiState.value = uiState.value.copy(
            deviceAuthState = DeviceAuthState(),
            bootstrapInput = "",
            deviceLabelInput = "",
            status = "Cleared local device credential",
        )
        FolderSyncScheduler.reschedule(getApplication())
    }

    private fun execute(loadingMessage: String, action: suspend () -> String) {
        uiState.value = uiState.value.copy(loading = true, status = loadingMessage)
        viewModelScope.launch {
            runCatching { action() }
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
            while (isActive) {
                val status = withContext(Dispatchers.IO) {
                    runCatching { repository.getContinuousFolderSyncStatus() }
                        .getOrDefault(FolderSyncServiceStatus())
                }
                uiState.value = uiState.value.copy(folderSyncStatus = status)
                delay(1_000)
            }
        }
    }

    private data class GalleryLoadSnapshot(
        val mode: GalleryViewMode,
        val currentDirectoryDocumentId: String,
        val currentDirectoryPath: String,
        val breadcrumbs: List<GalleryBreadcrumbItem>,
        val directories: List<GalleryDirectoryItem>,
        val images: List<GalleryImageItem>,
    )

    private fun loadGalleryState(): GalleryLoadSnapshot {
        return when (uiState.value.galleryMode) {
            GalleryViewMode.FLATTENED_ALL_IMAGES -> loadFlattenedGalleryState()
            GalleryViewMode.CURRENT_DIRECTORY -> loadCurrentDirectoryGalleryState(
                currentDirectoryDocumentId = uiState.value.galleryCurrentDirectoryDocumentId,
                currentDirectoryPath = uiState.value.galleryCurrentDirectoryPath,
                breadcrumbs = uiState.value.galleryBreadcrumbs,
            )
        }
    }

    private fun loadFlattenedGalleryState(): GalleryLoadSnapshot {
        val application = getApplication<Application>()
        val authority = "${application.packageName}.documents"
        val items = mutableListOf<GalleryImageItem>()
        val visitedDocumentIds = mutableSetOf<String>()

        collectGalleryImages(
            authority = authority,
            parentDocumentId = GALLERY_ROOT_DOCUMENT_ID,
            output = items,
            visitedDocumentIds = visitedDocumentIds,
        )
        return GalleryLoadSnapshot(
            mode = GalleryViewMode.FLATTENED_ALL_IMAGES,
            currentDirectoryDocumentId = GALLERY_ROOT_DOCUMENT_ID,
            currentDirectoryPath = GALLERY_ROOT_PATH,
            breadcrumbs = emptyList(),
            directories = emptyList(),
            images = items,
        )
    }

    private fun loadCurrentDirectoryGalleryState(
        currentDirectoryDocumentId: String,
        currentDirectoryPath: String,
        breadcrumbs: List<GalleryBreadcrumbItem>,
    ): GalleryLoadSnapshot {
        val application = getApplication<Application>()
        val authority = "${application.packageName}.documents"
        val listing = listGalleryDirectory(
            authority = authority,
            parentDocumentId = currentDirectoryDocumentId,
            currentDirectoryPath = currentDirectoryPath,
        )

        return GalleryLoadSnapshot(
            mode = GalleryViewMode.CURRENT_DIRECTORY,
            currentDirectoryDocumentId = currentDirectoryDocumentId,
            currentDirectoryPath = currentDirectoryPath,
            breadcrumbs = breadcrumbs,
            directories = listing.directories,
            images = listing.images,
        )
    }

    private data class GalleryDirectoryListing(
        val directories: List<GalleryDirectoryItem>,
        val images: List<GalleryImageItem>,
    )

    private fun listGalleryDirectory(
        authority: String,
        parentDocumentId: String,
        currentDirectoryPath: String,
    ): GalleryDirectoryListing {
        val directories = mutableListOf<GalleryDirectoryItem>()
        val images = mutableListOf<GalleryImageItem>()
        val resolver = getApplication<Application>().contentResolver
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            IronmeshDocumentColumns.COLUMN_REMOTE_PATH,
            IronmeshDocumentColumns.COLUMN_IMAGE_WIDTH,
            IronmeshDocumentColumns.COLUMN_IMAGE_HEIGHT,
            IronmeshDocumentColumns.COLUMN_CREATED_AT_UNIX_MS,
            IronmeshDocumentColumns.COLUMN_THUMBNAIL_STATUS,
        )

        val childrenUri = DocumentsContract.buildChildDocumentsUri(authority, parentDocumentId)
        resolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) {
                val documentId = cursor.stringOrNull(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    ?: continue
                val displayName = cursor.stringOrNull(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                    ?: documentId
                val mimeType = cursor.stringOrNull(DocumentsContract.Document.COLUMN_MIME_TYPE)
                    ?: continue
                val remotePath = cursor.stringOrNull(IronmeshDocumentColumns.COLUMN_REMOTE_PATH)

                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    directories += GalleryDirectoryItem(
                        documentId = documentId,
                        displayName = displayName,
                        pathLabel = normalizeGalleryDirectoryPath(
                            remotePath ?: childGalleryPath(currentDirectoryPath, displayName),
                        ),
                    )
                    continue
                }

                if (!mimeType.startsWith("image/")) {
                    continue
                }

                images += GalleryImageItem(
                    documentUri = DocumentsContract.buildDocumentUri(authority, documentId),
                    displayName = displayName,
                    remotePath = remotePath ?: documentId,
                    mimeType = mimeType,
                    createdAtUnixMs = cursor.longOrNull(IronmeshDocumentColumns.COLUMN_CREATED_AT_UNIX_MS)
                        ?: cursor.longOrNull(DocumentsContract.Document.COLUMN_LAST_MODIFIED),
                    width = cursor.intOrNull(IronmeshDocumentColumns.COLUMN_IMAGE_WIDTH),
                    height = cursor.intOrNull(IronmeshDocumentColumns.COLUMN_IMAGE_HEIGHT),
                    thumbnailStatus = cursor.stringOrNull(IronmeshDocumentColumns.COLUMN_THUMBNAIL_STATUS),
                )
            }
        }

        return GalleryDirectoryListing(
            directories = directories.sortedBy { it.displayName.lowercase() },
            images = images,
        )
    }

    private fun currentClientIdentityJson(): String? {
        return uiState.value.deviceAuthState.toClientIdentityJson()
    }

    private fun currentConnectionInput(): String {
        return uiState.value.deviceAuthState.preferredConnectionInput(uiState.value.baseUrl)
    }

    private fun currentServerCaPem(): String? {
        return uiState.value.deviceAuthState.serverCaPem?.takeIf { it.isNotBlank() }
    }

    private fun collectGalleryImages(
        authority: String,
        parentDocumentId: String,
        output: MutableList<GalleryImageItem>,
        visitedDocumentIds: MutableSet<String>,
    ) {
        if (!visitedDocumentIds.add(parentDocumentId)) {
            return
        }
        val resolver = getApplication<Application>().contentResolver
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            IronmeshDocumentColumns.COLUMN_REMOTE_PATH,
            IronmeshDocumentColumns.COLUMN_IMAGE_WIDTH,
            IronmeshDocumentColumns.COLUMN_IMAGE_HEIGHT,
            IronmeshDocumentColumns.COLUMN_CREATED_AT_UNIX_MS,
            IronmeshDocumentColumns.COLUMN_THUMBNAIL_STATUS,
        )

        val childrenUri = DocumentsContract.buildChildDocumentsUri(authority, parentDocumentId)
        resolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) {
                val documentId = cursor.stringOrNull(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    ?: continue
                val mimeType = cursor.stringOrNull(DocumentsContract.Document.COLUMN_MIME_TYPE)
                    ?: continue

                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    collectGalleryImages(authority, documentId, output, visitedDocumentIds)
                    continue
                }

                if (!mimeType.startsWith("image/")) {
                    continue
                }

                output += GalleryImageItem(
                    documentUri = DocumentsContract.buildDocumentUri(authority, documentId),
                    displayName = cursor.stringOrNull(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                        ?: documentId,
                    remotePath = cursor.stringOrNull(IronmeshDocumentColumns.COLUMN_REMOTE_PATH)
                        ?: documentId,
                    mimeType = mimeType,
                    createdAtUnixMs = cursor.longOrNull(IronmeshDocumentColumns.COLUMN_CREATED_AT_UNIX_MS)
                        ?: cursor.longOrNull(DocumentsContract.Document.COLUMN_LAST_MODIFIED),
                    width = cursor.intOrNull(IronmeshDocumentColumns.COLUMN_IMAGE_WIDTH),
                    height = cursor.intOrNull(IronmeshDocumentColumns.COLUMN_IMAGE_HEIGHT),
                    thumbnailStatus = cursor.stringOrNull(IronmeshDocumentColumns.COLUMN_THUMBNAIL_STATUS),
                )
            }
        }
    }

    private fun sortGallery(
        items: List<GalleryImageItem>,
        sort: GallerySortOption,
    ): List<GalleryImageItem> {
        return items.sortedWith(
            when (sort) {
                GallerySortOption.CREATION_TIME -> compareByDescending<GalleryImageItem> {
                    it.createdAtUnixMs ?: Long.MIN_VALUE
                }.thenBy { it.displayName.lowercase() }
                GallerySortOption.NAME -> compareBy<GalleryImageItem> {
                    it.displayName.lowercase()
                }.thenBy { it.remotePath.lowercase() }
            },
        )
    }

    private fun childGalleryPath(
        parentPath: String,
        displayName: String,
    ): String {
        val cleanParent = parentPath.removePrefix("/").trimEnd('/')
        val cleanChild = displayName.trim().trim('/')
        return when {
            cleanChild.isBlank() -> GALLERY_ROOT_PATH
            cleanParent.isBlank() -> "$cleanChild/"
            else -> "$cleanParent/$cleanChild/"
        }
    }

    private fun normalizeGalleryDirectoryPath(path: String): String {
        val normalized = path.trim().trim('/')
        return if (normalized.isBlank()) GALLERY_ROOT_PATH else "$normalized/"
    }
}
