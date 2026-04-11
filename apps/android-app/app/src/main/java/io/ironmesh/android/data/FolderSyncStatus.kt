package io.ironmesh.android.data

data class FolderSyncServiceStatus(
    val serviceState: String = "stopped",
    val serviceMessage: String = "Continuous sync is stopped",
    val profiles: List<FolderSyncProfileStatus> = emptyList(),
    val updatedUnixMs: Long = 0L,
    val profileCount: Long = 0L,
    val activeProfileCount: Long = 0L,
    val syncingProfileCount: Long = 0L,
    val errorProfileCount: Long = 0L,
    val startingProfileCount: Long = 0L,
    val runningProfileCount: Long = 0L,
    val currentActivity: String = "",
    val activeSummary: String = "",
    val lastSuccessUnixMs: Long? = null,
)

data class FolderSyncProfileStatus(
    val profileId: String = "",
    val label: String = "",
    val state: String = "stopped",
    val message: String = "",
    val updatedUnixMs: Long = 0L,
    val phase: String = "",
    val activity: String = "",
    val scopeLabel: String = "<root>",
    val rootDir: String = "",
    val localTreeUri: String? = null,
    val connectionTarget: String? = null,
    val storageMode: String = "",
    val watchMode: String = "",
    val runMode: String = "",
    val lastSuccessUnixMs: Long? = null,
    val lastError: String? = null,
    val metrics: FolderSyncRuntimeMetrics = FolderSyncRuntimeMetrics(),
)

data class FolderSyncRuntimeMetrics(
    val localEntryCount: Long = 0L,
    val localFileCount: Long = 0L,
    val localDirectoryCount: Long = 0L,
    val remoteEntryCount: Long = 0L,
    val remoteFileCount: Long = 0L,
    val remoteDirectoryCount: Long = 0L,
    val changedPathCount: Long = 0L,
    val uploadedFileCount: Long = 0L,
    val downloadedFileCount: Long = 0L,
    val deletedRemoteFileCount: Long = 0L,
    val removedLocalPathCount: Long = 0L,
    val ensuredDirectoryCount: Long = 0L,
    val preservedLocalFileCount: Long = 0L,
    val startupConflictCount: Long = 0L,
)
