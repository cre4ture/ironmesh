package io.ironmesh.android.saf

import android.content.res.AssetFileDescriptor
import android.database.Cursor
import android.database.MatrixCursor
import android.graphics.Point
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsProvider
import android.util.Log
import android.webkit.MimeTypeMap
import io.ironmesh.android.api.StoreIndexEntry
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import kotlinx.coroutines.runBlocking
import java.io.FileNotFoundException
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap

class IronmeshDocumentsProvider : DocumentsProvider() {
    private val repository = IronmeshRepository()
    private val documentEntries = ConcurrentHashMap<String, StoreIndexEntry>()

    override fun onCreate(): Boolean = true

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val result = MatrixCursor(resolveRootProjection(projection))
        val row = result.newRow()
        IronmeshCursorRows.populateRootRow(
            cursor = result,
            row = row,
            rootId = ROOT_ID,
            documentId = rootDocumentId(),
            title = ROOT_TITLE,
            summary = "Ironmesh distributed storage",
            flags =
            DocumentsContract.Root.FLAG_SUPPORTS_CREATE or
                DocumentsContract.Root.FLAG_SUPPORTS_IS_CHILD,
            mimeTypes = "*/*",
            icon = android.R.drawable.sym_def_app_icon,
        )
        return result
    }

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val result = MatrixCursor(resolveDocumentProjection(projection))
        includeDocumentRow(result, documentId)
        return result
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        val result = MatrixCursor(resolveDocumentProjection(projection))
        val parent = parseDocumentId(parentDocumentId)

        if (parent.kind != DocumentKind.Directory) {
            return result
        }

        val prefix = parent.path.takeIf { it.isNotBlank() }
        val entries = runBlocking {
            loadDirectoryEntries(prefix)
        }

        entries.forEach { entry ->
            if (entry.entry_type == "prefix") {
                val dirPath = entry.path.trimEnd('/')
                includeDirectory(result, directoryDocumentId(dirPath), dirPath)
            } else {
                includeFile(result, fileDocumentId(entry.path), entry)
            }
        }

        return result
    }

    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
        val parent = parseDocumentId(parentDocumentId)
        val child = parseDocumentId(documentId)
        if (parent.kind != DocumentKind.Directory) {
            return false
        }
        if (parent.path.isBlank()) {
            return child.path.isNotBlank()
        }
        return child.path.startsWith(parent.path.trimEnd('/') + "/")
    }

    override fun createDocument(
        parentDocumentId: String,
        mimeType: String,
        displayName: String,
    ): String {
        val parent = parseDocumentId(parentDocumentId)
        if (parent.kind != DocumentKind.Directory) {
            throw FileNotFoundException("parent is not a directory")
        }

        val key = buildChildPath(parent.path, displayName)
        runBlocking {
            repository.putObjectBytes(
                resolveBaseUrl(),
                key,
                ByteArray(0),
                resolveServerCaPem(),
                resolveAuthToken(),
            )
        }
        return fileDocumentId(key)
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        val target = parseDocumentId(documentId)
        if (target.kind != DocumentKind.File) {
            throw FileNotFoundException("not a file document")
        }

        return if (mode.contains('w')) {
            val pipe = ParcelFileDescriptor.createPipe()
            val readSide = pipe[0]
            val writeSide = pipe[1]

            Thread {
                ParcelFileDescriptor.AutoCloseInputStream(readSide).use { input ->
                    runBlocking {
                        repository.streamPutObject(
                            resolveBaseUrl(),
                            target.path,
                            input,
                            resolveServerCaPem(),
                            resolveAuthToken(),
                        )
                    }
                }
            }.start()

            writeSide
        } else {
            val pipe = ParcelFileDescriptor.createPipe()
            val readSide = pipe[0]
            val writeSide = pipe[1]

            Thread {
                ParcelFileDescriptor.AutoCloseOutputStream(writeSide).use { output ->
                    try {
                        runBlocking {
                            repository.streamObjectTo(
                                resolveBaseUrl(),
                                target.path,
                                output,
                                serverCaPem = resolveServerCaPem(),
                                authToken = resolveAuthToken(),
                            )
                        }
                        output.flush()
                    } catch (e: IOException) {
                        Log.w(TAG, "Client closed pipe while streaming: ${e.message}")
                    } catch (e: Exception) {
                        Log.e(TAG, "Error streaming object", e)
                    }
                }
            }.start()

            readSide
        }
    }

    override fun openDocumentThumbnail(
        documentId: String,
        sizeHint: Point,
        signal: CancellationSignal?,
    ): AssetFileDescriptor {
        val target = parseDocumentId(documentId)
        if (target.kind != DocumentKind.File) {
            throw FileNotFoundException("not a file document")
        }

        val entry = resolveFileEntry(target.path)
        val thumbnailUrl = entry.media?.thumbnail?.url
            ?: throw FileNotFoundException("thumbnail not available")

        try {
            val pipe = ParcelFileDescriptor.createPipe()
            val readSide = pipe[0]
            val writeSide = pipe[1]

            Thread {
                ParcelFileDescriptor.AutoCloseOutputStream(writeSide).use { output ->
                    try {
                        runBlocking {
                            repository.streamRelativeUrlTo(
                                resolveBaseUrl(),
                                thumbnailUrl,
                                output,
                                resolveServerCaPem(),
                                resolveAuthToken(),
                            )
                        }
                        output.flush()
                    } catch (e: IOException) {
                        Log.w(TAG, "Client closed thumbnail pipe: ${e.message}")
                    } catch (e: Exception) {
                        Log.e(TAG, "Error streaming thumbnail", e)
                    }
                }
            }.start()

            return AssetFileDescriptor(readSide, 0, AssetFileDescriptor.UNKNOWN_LENGTH)
        } catch (e: IOException) {
            throw FileNotFoundException("failed to open thumbnail: ${e.message}")
        }
    }

    private fun includeDocumentRow(cursor: MatrixCursor, documentId: String) {
        when (val parsed = parseDocumentId(documentId)) {
            ParsedDocument(DocumentKind.Directory, "") -> includeDirectory(cursor, documentId, ROOT_TITLE)
            ParsedDocument(DocumentKind.Directory, parsed.path) -> {
                includeDirectory(cursor, documentId, parsed.path.substringAfterLast('/'))
            }
            ParsedDocument(DocumentKind.File, parsed.path) -> {
                includeFile(cursor, documentId, resolveFileEntry(parsed.path))
            }
        }
    }

    private fun includeDirectory(cursor: MatrixCursor, documentId: String, name: String) {
        val row = cursor.newRow()
        IronmeshCursorRows.populateDirectoryRow(cursor, row, documentId, name)
    }

    private fun includeFile(cursor: MatrixCursor, documentId: String, entry: StoreIndexEntry) {
        val fullPath = entry.path
        val fileName = fullPath.substringAfterLast('/')
        val row = cursor.newRow()
        IronmeshCursorRows.populateFileRow(
            cursor = cursor,
            row = row,
            documentId = documentId,
            entry = entry,
            fallbackMimeType = mimeForName(fileName),
            summary = buildSummary(entry),
        )
    }

    private suspend fun loadDirectoryEntries(prefix: String?): List<StoreIndexEntry> {
        val entries = repository.storeIndex(
            baseUrl = resolveBaseUrl(),
            prefix = prefix,
            depth = 1,
            snapshot = null,
            serverCaPem = resolveServerCaPem(),
            authToken = resolveAuthToken(),
        )

        entries.forEach { entry ->
            if (entry.entry_type == "key") {
                documentEntries[entry.path] = entry
            }
        }

        return entries
    }

    private fun resolveFileEntry(path: String): StoreIndexEntry {
        documentEntries[path]?.let { return it }

        val parentPrefix = path.substringBeforeLast('/', "")
        val loaded = runBlocking {
            loadDirectoryEntries(parentPrefix.takeIf { it.isNotBlank() })
        }
        loaded.firstOrNull { it.entry_type == "key" && it.path == path }?.let { return it }

        return StoreIndexEntry(
            path = path,
            entry_type = "key",
            media = null,
        )
    }

    private fun buildSummary(entry: StoreIndexEntry): String? {
        val parts = mutableListOf<String>()
        entry.media?.let { media ->
            if (media.width != null && media.height != null) {
                parts += "${media.width} x ${media.height}"
            }
            if (media.status.isNotBlank()) {
                parts += media.status
            }
        }
        return parts.takeIf { it.isNotEmpty() }?.joinToString(" - ")
    }

    private fun resolveBaseUrl(): String {
        val context = context ?: return IronmeshPreferences.DEFAULT_BASE_URL
        val auth = IronmeshPreferences.getDeviceAuthState(context)
        val baseUrl = auth.serverBaseUrl.ifBlank { IronmeshPreferences.getBaseUrl(context) }
        return repository.sanitizeBaseUrl(baseUrl)
    }

    private fun resolveAuthToken(): String? {
        val context = context ?: return null
        return IronmeshPreferences.getDeviceAuthState(context)
            .deviceToken
            .takeIf { it.isNotBlank() }
    }

    private fun resolveServerCaPem(): String? {
        val context = context ?: return null
        return IronmeshPreferences.getDeviceAuthState(context)
            .serverCaPem
            ?.takeIf { it.isNotBlank() }
    }

    private fun resolveRootProjection(projection: Array<out String>?): Array<String> {
        return projection?.let { source ->
            Array(source.size) { index -> source[index] }
        } ?: arrayOf(
            DocumentsContract.Root.COLUMN_ROOT_ID,
            DocumentsContract.Root.COLUMN_DOCUMENT_ID,
            DocumentsContract.Root.COLUMN_TITLE,
            DocumentsContract.Root.COLUMN_SUMMARY,
            DocumentsContract.Root.COLUMN_FLAGS,
            DocumentsContract.Root.COLUMN_MIME_TYPES,
            DocumentsContract.Root.COLUMN_ICON,
        )
    }

    private fun resolveDocumentProjection(projection: Array<out String>?): Array<String> {
        return projection?.let { source ->
            Array(source.size) { index -> source[index] }
        } ?: arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_FLAGS,
            DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            DocumentsContract.Document.COLUMN_SUMMARY,
            IronmeshDocumentColumns.COLUMN_REMOTE_PATH,
            IronmeshDocumentColumns.COLUMN_IMAGE_WIDTH,
            IronmeshDocumentColumns.COLUMN_IMAGE_HEIGHT,
            IronmeshDocumentColumns.COLUMN_CREATED_AT_UNIX_MS,
            IronmeshDocumentColumns.COLUMN_THUMBNAIL_STATUS,
            IronmeshDocumentColumns.COLUMN_THUMBNAIL_WIDTH,
            IronmeshDocumentColumns.COLUMN_THUMBNAIL_HEIGHT,
        )
    }

    private fun rootDocumentId(): String = "dir:"

    private fun directoryDocumentId(path: String): String =
        if (path.isBlank()) {
            rootDocumentId()
        } else {
            "dir:${path.trim('/')}"
        }

    private fun fileDocumentId(path: String): String = "file:${path.trim('/')}"

    private fun parseDocumentId(documentId: String): ParsedDocument {
        return when {
            documentId == "dir:" -> ParsedDocument(DocumentKind.Directory, "")
            documentId.startsWith("dir:") -> ParsedDocument(
                DocumentKind.Directory,
                documentId.removePrefix("dir:").trim('/'),
            )
            documentId.startsWith("file:") -> ParsedDocument(
                DocumentKind.File,
                documentId.removePrefix("file:").trim('/'),
            )
            else -> throw FileNotFoundException("unknown document id: $documentId")
        }
    }

    private fun buildChildPath(parentPath: String, displayName: String): String {
        val normalized = displayName.trim().trim('/')
        if (normalized.isBlank()) {
            throw FileNotFoundException("invalid display name")
        }
        return if (parentPath.isBlank()) normalized else "${parentPath.trim('/')}/$normalized"
    }

    private fun mimeForName(name: String): String {
        val extension = name.substringAfterLast('.', "").lowercase()
        if (extension.isBlank()) return "application/octet-stream"
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
            ?: "application/octet-stream"
    }

    private enum class DocumentKind {
        Directory,
        File,
    }

    private data class ParsedDocument(
        val kind: DocumentKind,
        val path: String,
    )

    private companion object {
        private const val TAG = "IronmeshDocumentsProvider"
        private const val ROOT_ID = "ironmesh-root"
        private const val ROOT_TITLE = "Ironmesh"
    }
}
