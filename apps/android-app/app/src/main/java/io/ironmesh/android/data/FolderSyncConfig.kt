package io.ironmesh.android.data

data class FolderSyncConfig(
    val id: String,
    val label: String,
    val prefix: String,
    val localFolder: String,
    val depth: Int = 64,
    val enabled: Boolean = true,
)

data class FolderSyncRuntimeState(
    val fileSignatures: Map<String, String> = emptyMap(),
)
