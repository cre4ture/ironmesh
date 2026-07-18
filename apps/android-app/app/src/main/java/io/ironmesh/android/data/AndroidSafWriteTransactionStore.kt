package io.ironmesh.android.data

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import java.io.IOException
import java.util.UUID

internal class AndroidSafWriteTransactionStore private constructor(
    private val resolver: ContentResolver,
    private val parentUri: Uri,
    private val targetName: String,
    private val mimeType: String,
    initialTargetUri: Uri?,
    private var stagingUri: Uri?,
    private val renameSupported: Boolean,
) : SafWriteTransactionStore {
    override val targetExists: Boolean = initialTargetUri != null

    private var targetUri = initialTargetUri
    private var backupUri: Uri? = null
    private var targetPrepared = false
    private var targetCreatedDuringCommit = false

    override fun prepareTargetForReplace() {
        check(targetExists) { "Cannot prepare a missing SAF target" }
        check(!targetPrepared) { "SAF target is already prepared" }

        if (renameSupported) {
            val originalTargetUri = checkNotNull(targetUri)
            backupUri = renameDocument(originalTargetUri, newSafTemporaryName())
            targetUri = null
            targetPrepared = true
            return
        }

        val newBackupUri = createTemporaryDocument()
        backupUri = newBackupUri
        copyDocument(checkNotNull(targetUri), newBackupUri)
        targetPrepared = true
    }

    override fun promoteStaging() {
        val currentStagingUri = checkNotNull(stagingUri) { "SAF staging document is missing" }
        if (renameSupported) {
            targetUri = renameDocument(currentStagingUri, targetName)
            stagingUri = null
            return
        }

        val destinationUri = targetUri ?: createTargetDocument().also {
            targetUri = it
            targetCreatedDuringCommit = true
        }
        copyDocument(currentStagingUri, destinationUri)
        deleteDocument(currentStagingUri, "staging")
        stagingUri = null
    }

    override fun restoreTarget() {
        if (targetExists) {
            if (!targetPrepared) {
                return
            }
            val currentBackupUri = checkNotNull(backupUri) { "Prepared SAF target has no backup" }
            if (renameSupported) {
                targetUri = renameDocument(currentBackupUri, targetName)
                backupUri = null
            } else {
                copyDocument(currentBackupUri, checkNotNull(targetUri))
            }
            return
        }

        if (targetCreatedDuringCommit) {
            targetUri?.let { createdTargetUri ->
                deleteDocument(createdTargetUri, "partially promoted target")
            }
            targetUri = null
            targetCreatedDuringCommit = false
        }
    }

    override fun deleteBackup() {
        backupUri?.let { currentBackupUri ->
            deleteDocument(currentBackupUri, "backup")
            backupUri = null
        }
    }

    override fun deleteStaging() {
        stagingUri?.let { currentStagingUri ->
            deleteDocument(currentStagingUri, "staging")
            stagingUri = null
        }
    }

    private fun createTargetDocument(): Uri {
        return DocumentsContract.createDocument(resolver, parentUri, mimeType, targetName)
            ?: throw IOException("Failed to create SAF target document $targetName")
    }

    private fun createTemporaryDocument(): Uri {
        return DocumentsContract.createDocument(resolver, parentUri, mimeType, newSafTemporaryName())
            ?: throw IOException("Failed to create SAF temporary document for $targetName")
    }

    private fun renameDocument(documentUri: Uri, displayName: String): Uri {
        return DocumentsContract.renameDocument(resolver, documentUri, displayName)
            ?: throw IOException("Failed to rename SAF document to $displayName")
    }

    private fun copyDocument(sourceUri: Uri, destinationUri: Uri) {
        val input = resolver.openInputStream(sourceUri)
            ?: throw IOException("Failed to open SAF source document for $targetName")
        input.use { source ->
            val output = resolver.openOutputStream(destinationUri, "wt")
                ?: throw IOException("Failed to open SAF destination document for $targetName")
            output.use { destination ->
                source.copyTo(destination)
            }
        }
    }

    private fun deleteDocument(documentUri: Uri, role: String) {
        if (!DocumentsContract.deleteDocument(resolver, documentUri)) {
            throw IOException("Failed to delete SAF $role document for $targetName")
        }
    }

    companion object {
        /**
         * Creates a transaction backed by official DocumentsContract operations.
         *
         * SAF has no provider-independent atomic replace primitive. Providers advertising rename
         * support use a backup/rename sequence, which still has a short interval without the final
         * target name. Other providers use a copy/backup fallback; readers can observe partial bytes
         * during promotion or rollback. Both paths preserve a recoverable backup if rollback fails.
         */
        fun open(
            resolver: ContentResolver,
            parentUri: Uri,
            targetName: String,
            mimeType: String,
            targetUri: Uri?,
            onFinalized: () -> Unit,
        ): SafTransactionalOutputStream {
            val stagingUri = DocumentsContract.createDocument(
                resolver,
                parentUri,
                mimeType,
                newSafTemporaryName(),
            ) ?: throw IOException("Failed to create SAF staging document for $targetName")

            try {
                val renameSupported = supportsRename(resolver, stagingUri) &&
                    (targetUri == null || supportsRename(resolver, targetUri))
                val store = AndroidSafWriteTransactionStore(
                    resolver = resolver,
                    parentUri = parentUri,
                    targetName = targetName,
                    mimeType = mimeType,
                    initialTargetUri = targetUri,
                    stagingUri = stagingUri,
                    renameSupported = renameSupported,
                )
                val output = resolver.openOutputStream(stagingUri, "wt")
                    ?: throw IOException("Failed to open SAF staging document for $targetName")
                return SafTransactionalOutputStream(
                    delegate = output,
                    coordinator = SafWriteTransactionCoordinator(store),
                    onFinalized = onFinalized,
                )
            } catch (openError: Throwable) {
                try {
                    DocumentsContract.deleteDocument(resolver, stagingUri)
                } catch (cleanupError: Throwable) {
                    openError.addSuppressed(cleanupError)
                }
                throw openError
            }
        }

        private fun supportsRename(resolver: ContentResolver, documentUri: Uri): Boolean {
            val projection = arrayOf(DocumentsContract.Document.COLUMN_FLAGS)
            resolver.query(documentUri, projection, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val flags = cursor.getInt(0)
                    return flags and DocumentsContract.Document.FLAG_SUPPORTS_RENAME != 0
                }
            }
            return false
        }
    }
}

private fun newSafTemporaryName(): String = ".ironmesh-part-${UUID.randomUUID()}.tmp"
