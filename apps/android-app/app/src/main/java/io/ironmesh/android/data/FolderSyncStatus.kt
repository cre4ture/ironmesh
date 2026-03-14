package io.ironmesh.android.data

data class FolderSyncServiceStatus(
    val serviceState: String = "stopped",
    val serviceMessage: String = "Continuous sync is stopped",
    val profiles: List<FolderSyncProfileStatus> = emptyList(),
    val updatedUnixMs: Long = 0L,
)

data class FolderSyncProfileStatus(
    val profileId: String = "",
    val label: String = "",
    val state: String = "stopped",
    val message: String = "",
    val updatedUnixMs: Long = 0L,
)
