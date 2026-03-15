package io.ironmesh.android.data

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.webkit.MimeTypeMap
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream

object RustSafBridge {
    @Volatile
    private var appContext: Context? = null

    @JvmStatic
    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    @JvmStatic
    fun listTreeSnapshot(treeUriString: String): String {
        val resolver = requireResolver()
        val treeUri = Uri.parse(treeUriString)
        val rootDocumentId = DocumentsContract.getTreeDocumentId(treeUri)
        val entries = JSONArray()
        collectEntries(
            resolver = resolver,
            treeUri = treeUri,
            parentDocumentId = rootDocumentId,
            prefix = "",
            visitedDocumentIds = mutableSetOf(),
            output = entries,
        )
        return entries.toString()
    }

    @JvmStatic
    fun openTreeFileInput(treeUriString: String, relativePath: String): InputStream {
        val resolver = requireResolver()
        val treeUri = Uri.parse(treeUriString)
        val documentUri = resolveExistingDocumentUri(resolver, treeUri, relativePath)
            ?: error("No SAF document found for $relativePath")
        return resolver.openInputStream(documentUri)
            ?: error("Failed to open SAF input stream for $relativePath")
    }

    @JvmStatic
    fun openTreeFileOutput(treeUriString: String, relativePath: String): OutputStream {
        val resolver = requireResolver()
        val treeUri = Uri.parse(treeUriString)
        val documentUri = resolveOrCreateFileDocumentUri(resolver, treeUri, relativePath)
        return resolver.openOutputStream(documentUri, "wt")
            ?: error("Failed to open SAF output stream for $relativePath")
    }

    @JvmStatic
    fun ensureTreeDirectory(treeUriString: String, relativePath: String) {
        val resolver = requireResolver()
        val treeUri = Uri.parse(treeUriString)
        ensureDirectoryUri(resolver, treeUri, relativePath)
    }

    @JvmStatic
    fun deleteTreePath(treeUriString: String, relativePath: String): Boolean {
        val resolver = requireResolver()
        val treeUri = Uri.parse(treeUriString)
        val documentUri = resolveExistingDocumentUri(resolver, treeUri, relativePath) ?: return false
        return DocumentsContract.deleteDocument(resolver, documentUri)
    }

    private fun requireResolver(): ContentResolver {
        return appContext?.contentResolver
            ?: error("RustSafBridge is not initialized")
    }

    private fun collectEntries(
        resolver: ContentResolver,
        treeUri: Uri,
        parentDocumentId: String,
        prefix: String,
        visitedDocumentIds: MutableSet<String>,
        output: JSONArray,
    ) {
        if (!visitedDocumentIds.add(parentDocumentId)) {
            return
        }

        for (child in queryChildren(resolver, treeUri, parentDocumentId)) {
            val relativePath = if (prefix.isBlank()) {
                child.displayName
            } else {
                "$prefix/${child.displayName}"
            }
            if (shouldIgnorePath(relativePath)) {
                continue
            }

            output.put(
                JSONObject()
                    .put("path", relativePath)
                    .put("kind", if (child.isDirectory) "directory" else "file")
                    .put("sizeBytes", child.sizeBytes)
                    .put("modifiedUnixMs", child.modifiedUnixMs),
            )

            if (child.isDirectory) {
                collectEntries(
                    resolver = resolver,
                    treeUri = treeUri,
                    parentDocumentId = child.documentId,
                    prefix = relativePath,
                    visitedDocumentIds = visitedDocumentIds,
                    output = output,
                )
            }
        }
    }

    private fun resolveExistingDocumentUri(
        resolver: ContentResolver,
        treeUri: Uri,
        relativePath: String,
    ): Uri? {
        val normalized = normalizeRelativePath(relativePath)
        var currentDocumentId = DocumentsContract.getTreeDocumentId(treeUri)
        var currentDocumentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, currentDocumentId)
        if (normalized.isBlank()) {
            return currentDocumentUri
        }

        normalized.split('/').forEach { segment ->
            val child = queryChildren(resolver, treeUri, currentDocumentId)
                .firstOrNull { it.displayName == segment }
                ?: return null
            currentDocumentId = child.documentId
            currentDocumentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, currentDocumentId)
        }

        return currentDocumentUri
    }

    private fun ensureDirectoryUri(
        resolver: ContentResolver,
        treeUri: Uri,
        relativePath: String,
    ): Uri {
        val normalized = normalizeRelativePath(relativePath)
        var currentDocumentId = DocumentsContract.getTreeDocumentId(treeUri)
        var currentDocumentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, currentDocumentId)
        if (normalized.isBlank()) {
            return currentDocumentUri
        }

        normalized.split('/').forEach { segment ->
            val existing = queryChildren(resolver, treeUri, currentDocumentId)
                .firstOrNull { it.displayName == segment }
            if (existing != null) {
                check(existing.isDirectory) { "Expected directory at $segment inside $relativePath" }
                currentDocumentId = existing.documentId
                currentDocumentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, currentDocumentId)
            } else {
                val createdUri = DocumentsContract.createDocument(
                    resolver,
                    currentDocumentUri,
                    DocumentsContract.Document.MIME_TYPE_DIR,
                    segment,
                ) ?: error("Failed to create SAF directory $segment inside $relativePath")
                currentDocumentId = DocumentsContract.getDocumentId(createdUri)
                currentDocumentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, currentDocumentId)
            }
        }

        return currentDocumentUri
    }

    private fun resolveOrCreateFileDocumentUri(
        resolver: ContentResolver,
        treeUri: Uri,
        relativePath: String,
    ): Uri {
        val normalized = normalizeRelativePath(relativePath)
        require(normalized.isNotBlank()) { "Relative path must not be empty" }

        val fileName = normalized.substringAfterLast('/')
        val parentPath = normalized.substringBeforeLast('/', "")
        val parentUri = ensureDirectoryUri(resolver, treeUri, parentPath)
        val parentDocumentId = DocumentsContract.getDocumentId(parentUri)
        val existing = queryChildren(resolver, treeUri, parentDocumentId)
            .firstOrNull { it.displayName == fileName }

        if (existing != null) {
            check(!existing.isDirectory) { "Expected file at $normalized but found directory" }
            return DocumentsContract.buildDocumentUriUsingTree(treeUri, existing.documentId)
        }

        return DocumentsContract.createDocument(
            resolver,
            parentUri,
            guessMimeType(fileName),
            fileName,
        ) ?: error("Failed to create SAF file $normalized")
    }

    private fun queryChildren(
        resolver: ContentResolver,
        treeUri: Uri,
        parentDocumentId: String,
    ): List<ChildDocument> {
        val children = mutableListOf<ChildDocument>()
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentDocumentId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
        )
        resolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            val idIndex = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameIndex = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeIndex = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
            val sizeIndex = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_SIZE)
            val modifiedIndex = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            while (cursor.moveToNext()) {
                val displayName = cursor.getString(nameIndex) ?: continue
                children += ChildDocument(
                    documentId = cursor.getString(idIndex),
                    displayName = displayName,
                    mimeType = cursor.getString(mimeIndex),
                    sizeBytes = cursor.getLong(sizeIndex).coerceAtLeast(0L),
                    modifiedUnixMs = cursor.getLong(modifiedIndex).coerceAtLeast(0L),
                )
            }
        }
        return children
    }

    private fun normalizeRelativePath(relativePath: String): String {
        return relativePath
            .trim()
            .replace('\\', '/')
            .trim('/')
            .split('/')
            .filter { it.isNotBlank() }
            .joinToString("/")
    }

    private fun shouldIgnorePath(relativePath: String): Boolean {
        val segments = normalizeRelativePath(relativePath).split('/')
        return segments.any { segment ->
            segment == ".ironmesh" ||
                segment == ".ironmesh-conflicts" ||
                segment == ".thumbnails" ||
                segment.contains(".ironmesh-part-")
        }
    }

    private fun guessMimeType(fileName: String): String {
        val extension = fileName.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
            ?: "application/octet-stream"
    }

    private data class ChildDocument(
        val documentId: String,
        val displayName: String,
        val mimeType: String?,
        val sizeBytes: Long,
        val modifiedUnixMs: Long,
    ) {
        val isDirectory: Boolean
            get() = mimeType == DocumentsContract.Document.MIME_TYPE_DIR
    }
}
