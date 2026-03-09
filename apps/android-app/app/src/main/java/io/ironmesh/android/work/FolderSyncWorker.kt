package io.ironmesh.android.work

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import io.ironmesh.android.data.FolderSyncConfig
import io.ironmesh.android.data.FolderSyncRuntimeState
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

class FolderSyncWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    private val repository = IronmeshRepository()

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val baseUrl = IronmeshPreferences.getBaseUrl(applicationContext)
        val authToken = IronmeshPreferences.getDeviceAuthState(applicationContext)
            .deviceToken
            .takeIf { it.isNotBlank() }
        val profiles = IronmeshPreferences
            .getFolderSyncConfigs(applicationContext)
            .filter { it.enabled }

        if (profiles.isEmpty()) {
            return@withContext Result.success()
        }

        val failures = mutableListOf<String>()

        for (profile in profiles) {
            runCatching {
                syncProfile(baseUrl, authToken, profile)
            }.onFailure { error ->
                failures += "${profile.label}: ${error.message ?: "unknown"}"
                Log.e(TAG, "folder sync failed for profile=${profile.id}", error)
            }
        }

        if (failures.isEmpty()) {
            Result.success()
        } else {
            Result.retry()
        }
    }

    private suspend fun syncProfile(baseUrl: String, authToken: String?, profile: FolderSyncConfig) {
        val scope = SyncPathScope(profile.prefix)
        val localRoot = File(profile.localFolder)
        if (!localRoot.exists()) {
            localRoot.mkdirs()
        }

        val previousState = IronmeshPreferences.getFolderSyncRuntimeState(
            applicationContext,
            profile.id,
        )

        val remoteEntries = repository.storeIndex(
            baseUrl = baseUrl,
            prefix = scope.remotePrefixOrNull(),
            depth = profile.depth.coerceAtLeast(1),
            snapshot = null,
            authToken = authToken,
        )

        val remoteFiles = mutableSetOf<String>()
        val remoteDirectories = mutableSetOf<String>()

        for (entry in remoteEntries) {
            val localPath = scope.remoteToLocal(entry.path) ?: continue
            if (localPath.isBlank()) {
                continue
            }

            val isDirectory = entry.entry_type == "prefix" || entry.path.endsWith("/")
            if (isDirectory) {
                remoteDirectories += localPath
            } else {
                remoteFiles += localPath
            }
        }

        // Materialize remote directories and missing files to local.
        for (directory in remoteDirectories.sortedBy { it.length }) {
            File(localRoot, directory).mkdirs()
        }

        for (relativePath in remoteFiles.sorted()) {
            val localFile = File(localRoot, relativePath)
            if (localFile.exists()) {
                continue
            }

            localFile.parentFile?.mkdirs()
            val remoteKey = scope.localToRemote(relativePath)
            FileOutputStream(localFile).use { output ->
                repository.streamObjectTo(baseUrl, remoteKey, output, authToken = authToken)
            }
        }

        val localBeforeUpload = scanLocalTree(localRoot)

        // Ensure local directory markers exist remotely.
        for (directory in localBeforeUpload.directories) {
            if (remoteDirectories.contains(directory)) {
                continue
            }
            val markerKey = scope.localToRemote(directory).trimEnd('/') + "/"
            repository.putObjectBytes(baseUrl, markerKey, ByteArray(0), authToken)
        }

        // Upload local new/changed files.
        for ((relativePath, signature) in localBeforeUpload.fileSignatures) {
            val signatureChanged = previousState.fileSignatures[relativePath] != signature
            val missingRemotely = !remoteFiles.contains(relativePath)
            if (!signatureChanged && !missingRemotely) {
                continue
            }

            val remoteKey = scope.localToRemote(relativePath)
            FileInputStream(File(localRoot, relativePath)).use { input ->
                repository.streamPutObject(baseUrl, remoteKey, input, authToken)
            }
        }

        // Propagate local file deletions when previously seen and still present remotely.
        val locallyDeleted = previousState.fileSignatures.keys - localBeforeUpload.fileSignatures.keys
        for (relativePath in locallyDeleted) {
            if (!remoteFiles.contains(relativePath)) {
                continue
            }

            val remoteKey = scope.localToRemote(relativePath)
            repository.deleteObject(baseUrl, remoteKey, authToken)
        }

        val finalState = scanLocalTree(localRoot)
        IronmeshPreferences.setFolderSyncRuntimeState(
            applicationContext,
            profile.id,
            FolderSyncRuntimeState(fileSignatures = finalState.fileSignatures),
        )

        Log.i(
            TAG,
            "synced profile=${profile.id} files=${finalState.fileSignatures.size} dirs=${finalState.directories.size}",
        )
    }

    private fun scanLocalTree(root: File): LocalScanState {
        if (!root.exists()) {
            return LocalScanState(emptyMap(), emptySet())
        }

        val files = mutableMapOf<String, String>()
        val directories = mutableSetOf<String>()

        root.walkTopDown().forEach { file ->
            if (file == root) {
                return@forEach
            }

            val relative = normalizeRelativePath(file.relativeTo(root).path)
            if (relative.isBlank()) {
                return@forEach
            }

            if (file.isDirectory) {
                directories += relative
                return@forEach
            }

            if (file.isFile) {
                files[relative] = signatureForFile(file)
            }
        }

        return LocalScanState(files, directories)
    }

    private fun signatureForFile(file: File): String {
        return "${file.length()}:${file.lastModified()}"
    }

    private fun normalizeRelativePath(path: String): String {
        return path
            .replace('\\', '/')
            .trim('/')
            .split('/')
            .filter { it.isNotBlank() }
            .joinToString("/")
    }

    private data class LocalScanState(
        val fileSignatures: Map<String, String>,
        val directories: Set<String>,
    )

    private class SyncPathScope(prefix: String) {
        private val normalizedPrefix: String = normalizePath(prefix)

        fun remotePrefixOrNull(): String? = normalizedPrefix.takeIf { it.isNotBlank() }

        fun remoteToLocal(remotePath: String): String? {
            val normalizedRemote = normalizePath(remotePath)
            if (normalizedRemote.isBlank()) {
                return null
            }

            if (normalizedPrefix.isBlank()) {
                return normalizedRemote
            }

            if (normalizedRemote == normalizedPrefix) {
                return ""
            }

            val scopedPrefix = "$normalizedPrefix/"
            return normalizedRemote
                .takeIf { it.startsWith(scopedPrefix) }
                ?.removePrefix(scopedPrefix)
        }

        fun localToRemote(localPath: String): String {
            val normalizedLocal = normalizePath(localPath)
            if (normalizedPrefix.isBlank()) {
                return normalizedLocal
            }
            return if (normalizedLocal.isBlank()) {
                normalizedPrefix
            } else {
                "$normalizedPrefix/$normalizedLocal"
            }
        }

        private fun normalizePath(path: String): String {
            return path
                .replace('\\', '/')
                .trim('/')
                .split('/')
                .filter { it.isNotBlank() }
                .joinToString("/")
        }
    }

    private companion object {
        private const val TAG = "FolderSyncWorker"
    }
}
