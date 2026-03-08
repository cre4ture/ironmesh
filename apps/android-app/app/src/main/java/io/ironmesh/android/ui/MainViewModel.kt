package io.ironmesh.android.ui

import android.app.Application
import android.net.Uri
import android.provider.DocumentsContract
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.ironmesh.android.data.FolderSyncConfig
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import io.ironmesh.android.saf.IronmeshDocumentColumns
import io.ironmesh.android.work.FolderSyncScheduler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

enum class GallerySortOption {
    CREATION_TIME,
    NAME,
}

enum class MainSection {
    SETTINGS,
    WEB_UI,
    GALLERY,
}

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

data class MainUiState(
    val baseUrl: String = IronmeshPreferences.DEFAULT_BASE_URL,
    val key: String = "demo-key",
    val payload: String = "hello from android",
    val status: String = "Ready",
    val replicationSummary: String = "",
    val objectBody: String = "",
    val syncProfiles: List<FolderSyncConfig> = emptyList(),
    val newSyncLabel: String = "",
    val newSyncPrefix: String = "",
    val newSyncLocalFolder: String = "",
    val selectedSection: MainSection = MainSection.SETTINGS,
    val webUiUrl: String = "",
    val galleryItems: List<GalleryImageItem> = emptyList(),
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
        uiState.value = uiState.value.copy(baseUrl = persistedBaseUrl)
        uiState.value = uiState.value.copy(syncProfiles = persistedProfiles)
        FolderSyncScheduler.reschedule(getApplication())
    }

    fun updateBaseUrl(value: String) {
        uiState.value = uiState.value.copy(baseUrl = value)
        IronmeshPreferences.setBaseUrl(getApplication(), value)
    }

    fun updateKey(value: String) {
        uiState.value = uiState.value.copy(key = value)
    }

    fun updatePayload(value: String) {
        uiState.value = uiState.value.copy(payload = value)
    }

    fun checkHealth() {
        execute("Checking health...") {
            val health = repository.health(uiState.value.baseUrl)
            "Health: online=${health.online} node=${health.node_id ?: "n/a"}"
        }
    }

    fun loadReplicationPlan() {
        execute("Loading replication plan...") {
            val plan = repository.replicationPlan(uiState.value.baseUrl)
            val keys = plan.items.take(5).joinToString { it.key }
            val summary = "under=${plan.under_replicated}, over=${plan.over_replicated}, items=${plan.items.size}" +
                if (keys.isNotBlank()) "\nSample: $keys" else ""
            uiState.value = uiState.value.copy(replicationSummary = summary)
            "Plan loaded"
        }
    }

    fun putObject() {
        execute("Uploading object...") {
            val statusCode = repository.putObject(
                uiState.value.baseUrl,
                uiState.value.key,
                uiState.value.payload,
            )
            "PUT ok: HTTP $statusCode"
        }
    }

    fun getObject() {
        execute("Downloading object...") {
            val body = repository.getObject(uiState.value.baseUrl, uiState.value.key)
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
        uiState.value = uiState.value.copy(newSyncLocalFolder = value)
    }

    fun selectSection(section: MainSection) {
        uiState.value = uiState.value.copy(selectedSection = section)
    }

    fun refreshGallery() {
        uiState.value = uiState.value.copy(galleryLoading = true, status = "Loading gallery...")
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    loadGalleryItems()
                }
            }
                .onSuccess { items ->
                    val sorted = sortGallery(items, uiState.value.gallerySort)
                    uiState.value = uiState.value.copy(
                        galleryItems = sorted,
                        galleryLoading = false,
                        status = "Gallery loaded: ${sorted.size} images",
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
        IronmeshPreferences.clearFolderSyncRuntimeState(getApplication(), profileId)
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
        val baseUrl = uiState.value.baseUrl
        uiState.value = uiState.value.copy(
            loading = true,
            selectedSection = MainSection.WEB_UI,
            status = "Starting embedded Web UI...",
        )
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    repository.startWebUi(baseUrl)
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

    private fun loadGalleryItems(): List<GalleryImageItem> {
        val application = getApplication<Application>()
        val authority = "${application.packageName}.documents"
        val rootDocumentId = "dir:"
        val items = mutableListOf<GalleryImageItem>()

        collectGalleryImages(
            authority = authority,
            parentDocumentId = rootDocumentId,
            output = items,
        )
        return items
    }

    private fun collectGalleryImages(
        authority: String,
        parentDocumentId: String,
        output: MutableList<GalleryImageItem>,
    ) {
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
                    collectGalleryImages(authority, documentId, output)
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
}
