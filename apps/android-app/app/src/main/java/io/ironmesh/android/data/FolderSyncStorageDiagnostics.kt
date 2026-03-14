package io.ironmesh.android.data

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import java.io.File

data class FolderSyncStorageDiagnostics(
    val rawSampleChildren: String,
    val treeUri: String?,
    val treeUriSource: String,
    val safSampleChildren: String,
)

object FolderSyncStorageDiagnosticsHelper {
    fun collect(
        contentResolver: ContentResolver,
        localFolder: String,
        explicitTreeUri: String?,
    ): FolderSyncStorageDiagnostics {
        val rawSampleChildren = File(localFolder)
            .listFiles()
            ?.take(5)
            ?.joinToString(", ") { child -> child.name }
            ?: "<unavailable>"

        val (treeUri, treeUriSource) = resolveTreeUri(localFolder, explicitTreeUri)
        val safSampleChildren = if (treeUri == null) {
            "<no tree uri>"
        } else {
            listTreeChildren(contentResolver, treeUri)
        }

        return FolderSyncStorageDiagnostics(
            rawSampleChildren = rawSampleChildren,
            treeUri = treeUri?.toString(),
            treeUriSource = treeUriSource,
            safSampleChildren = safSampleChildren,
        )
    }

    private fun resolveTreeUri(localFolder: String, explicitTreeUri: String?): Pair<Uri?, String> {
        explicitTreeUri
            ?.takeIf { it.isNotBlank() }
            ?.let { return Uri.parse(it) to "persisted" }

        return filesystemPathToTreeUri(localFolder)?.let { uri ->
            uri to "derived"
        } ?: (null to "none")
    }

    private fun filesystemPathToTreeUri(localFolder: String): Uri? {
        val normalized = localFolder.replace('\\', '/').trimEnd('/')
        val primaryPrefix = "/storage/emulated/0"
        if (!normalized.startsWith(primaryPrefix, ignoreCase = true)) {
            return null
        }

        val relativePath = normalized.removePrefix(primaryPrefix).trimStart('/')
        val documentId = if (relativePath.isBlank()) {
            "primary:"
        } else {
            "primary:$relativePath"
        }

        return DocumentsContract.buildTreeDocumentUri(
            "com.android.externalstorage.documents",
            documentId,
        )
    }

    private fun listTreeChildren(
        contentResolver: ContentResolver,
        treeUri: Uri,
    ): String {
        return runCatching {
            val treeDocumentId = DocumentsContract.getTreeDocumentId(treeUri)
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeDocumentId)
            val projection = arrayOf(
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            )
            contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
                val names = mutableListOf<String>()
                val nameIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val idIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                while (cursor.moveToNext() && names.size < 5) {
                    val displayName = if (nameIndex >= 0) cursor.getString(nameIndex) else null
                    val documentId = if (idIndex >= 0) cursor.getString(idIndex) else null
                    names += displayName?.takeIf { it.isNotBlank() }
                        ?: documentId?.substringAfterLast('/')
                        ?: "<unnamed>"
                }
                when {
                    names.isEmpty() -> "<empty>"
                    else -> names.joinToString(", ")
                }
            } ?: "<query failed>"
        }.getOrElse { error ->
            "<error: ${error.javaClass.simpleName}: ${error.message ?: "unknown"}>"
        }
    }
}
