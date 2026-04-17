package io.ironmesh.android.data

data class FolderSyncModificationHistory(
    val records: List<FolderSyncModificationRecord> = emptyList(),
    val nextBeforeId: Long? = null,
)

data class FolderSyncModificationRecord(
    val id: Long = 0L,
    val occurredUnixMs: Long = 0L,
    val operation: String = "",
    val outcome: String = "",
    val phase: String = "",
    val triggerSource: String = "",
    val localRelativePath: String = "",
    val remoteKey: String = "",
    val sizeBytes: Long? = null,
    val contentHash: String? = null,
    val scopeLabel: String = "",
    val rootDir: String = "",
    val connectionTarget: String = "",
    val errorText: String? = null,
)
