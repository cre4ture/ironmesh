package io.ironmesh.android.saf

import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsProvider
import android.webkit.MimeTypeMap
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import kotlinx.coroutines.runBlocking
import java.io.FileNotFoundException

class IronmeshDocumentsProvider : DocumentsProvider() {
    private val repository = IronmeshRepository()

    override fun onCreate(): Boolean = true

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val result = MatrixCursor(resolveRootProjection(projection))
        val row = result.newRow()
        row.add(DocumentsContract.Root.COLUMN_ROOT_ID, ROOT_ID)
        row.add(DocumentsContract.Root.COLUMN_DOCUMENT_ID, rootDocumentId())
        row.add(DocumentsContract.Root.COLUMN_TITLE, ROOT_TITLE)
        row.add(DocumentsContract.Root.COLUMN_SUMMARY, "Ironmesh distributed storage")
        row.add(
            DocumentsContract.Root.COLUMN_FLAGS,
            DocumentsContract.Root.FLAG_SUPPORTS_CREATE or
                DocumentsContract.Root.FLAG_SUPPORTS_IS_CHILD,
        )
        row.add(DocumentsContract.Root.COLUMN_MIME_TYPES, "*/*")
        row.add(DocumentsContract.Root.COLUMN_ICON, android.R.drawable.sym_def_app_icon)
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
            repository.storeIndex(
                baseUrl = resolveBaseUrl(),
                prefix = prefix,
                depth = 1,
                snapshot = null,
            )
        }

        entries.forEach { entry ->
            if (entry.entry_type == "prefix") {
                val dirPath = entry.path.trimEnd('/')
                includeDirectory(result, directoryDocumentId(dirPath), dirPath)
            } else {
                includeFile(result, fileDocumentId(entry.path), entry.path)
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
            repository.putObjectBytes(resolveBaseUrl(), key, ByteArray(0))
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
                    val bytes = input.readBytes()
                    runBlocking {
                        repository.putObjectBytes(resolveBaseUrl(), target.path, bytes)
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
                    val bytes = runBlocking {
                        repository.getObjectBytes(resolveBaseUrl(), target.path)
                    }
                    output.write(bytes)
                    output.flush()
                }
            }.start()

            readSide
        }
    }

    private fun includeDocumentRow(cursor: MatrixCursor, documentId: String) {
        when (val parsed = parseDocumentId(documentId)) {
            ParsedDocument(DocumentKind.Directory, "") -> includeDirectory(cursor, documentId, ROOT_TITLE)
            ParsedDocument(DocumentKind.Directory, parsed.path) -> {
                includeDirectory(cursor, documentId, parsed.path.substringAfterLast('/'))
            }
            ParsedDocument(DocumentKind.File, parsed.path) -> {
                includeFile(cursor, documentId, parsed.path)
            }
        }
    }

    private fun includeDirectory(cursor: MatrixCursor, documentId: String, name: String) {
        val row = cursor.newRow()
        row.add(DocumentsContract.Document.COLUMN_DOCUMENT_ID, documentId)
        row.add(DocumentsContract.Document.COLUMN_DISPLAY_NAME, name)
        row.add(DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.MIME_TYPE_DIR)
        row.add(
            DocumentsContract.Document.COLUMN_FLAGS,
            DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE,
        )
    }

    private fun includeFile(cursor: MatrixCursor, documentId: String, fullPath: String) {
        val fileName = fullPath.substringAfterLast('/')
        val mime = mimeForName(fileName)
        val row = cursor.newRow()
        row.add(DocumentsContract.Document.COLUMN_DOCUMENT_ID, documentId)
        row.add(DocumentsContract.Document.COLUMN_DISPLAY_NAME, fileName)
        row.add(DocumentsContract.Document.COLUMN_MIME_TYPE, mime)
        row.add(
            DocumentsContract.Document.COLUMN_FLAGS,
            DocumentsContract.Document.FLAG_SUPPORTS_WRITE,
        )
    }

    private fun resolveBaseUrl(): String {
        val context = context ?: return IronmeshPreferences.DEFAULT_BASE_URL
        return repository.sanitizeBaseUrl(IronmeshPreferences.getBaseUrl(context))
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
        private const val ROOT_ID = "ironmesh-root"
        private const val ROOT_TITLE = "Ironmesh"
    }
}
