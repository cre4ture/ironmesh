package io.ironmesh.android.data

import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsProvider
import java.io.File
import java.io.FileNotFoundException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class TestTreeDocumentsProvider : DocumentsProvider() {
    override fun onCreate(): Boolean = true

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val result = MatrixCursor(
            projection ?: arrayOf(
                DocumentsContract.Root.COLUMN_ROOT_ID,
                DocumentsContract.Root.COLUMN_DOCUMENT_ID,
                DocumentsContract.Root.COLUMN_TITLE,
                DocumentsContract.Root.COLUMN_FLAGS,
                DocumentsContract.Root.COLUMN_MIME_TYPES,
            ),
        )
        val row = result.newRow()
        row.add(DocumentsContract.Root.COLUMN_ROOT_ID, ROOT_ID)
        row.add(DocumentsContract.Root.COLUMN_DOCUMENT_ID, ROOT_DOCUMENT_ID)
        row.add(DocumentsContract.Root.COLUMN_TITLE, "Test SAF Root")
        row.add(
            DocumentsContract.Root.COLUMN_FLAGS,
            DocumentsContract.Root.FLAG_SUPPORTS_CREATE or DocumentsContract.Root.FLAG_SUPPORTS_IS_CHILD,
        )
        row.add(DocumentsContract.Root.COLUMN_MIME_TYPES, "*/*")
        return result
    }

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val result = MatrixCursor(resolveDocumentProjection(projection))
        includeDocument(result, documentId)
        return result
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        val result = MatrixCursor(resolveDocumentProjection(projection))
        val parentFile = fileForDocumentId(parentDocumentId)
        if (!parentFile.isDirectory) {
            return result
        }

        parentFile.listFiles()
            ?.sortedBy { it.name }
            ?.forEach { child ->
                includeDocument(result, documentIdForFile(child))
            }
        return result
    }

    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
        val parent = fileForDocumentId(parentDocumentId).canonicalFile
        val child = fileForDocumentId(documentId).canonicalFile
        return child != parent && child.path.startsWith(parent.path + File.separator)
    }

    override fun createDocument(parentDocumentId: String, mimeType: String, displayName: String): String {
        val parent = fileForDocumentId(parentDocumentId)
        if (!parent.isDirectory) {
            throw FileNotFoundException("parent is not a directory")
        }

        val child = File(parent, displayName)
        if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
            child.mkdirs()
        } else {
            child.parentFile?.mkdirs()
            if (!child.exists()) {
                child.createNewFile()
            }
        }
        notifyParentChanged(parentDocumentId)
        return documentIdForFile(child)
    }

    override fun deleteDocument(documentId: String) {
        val target = fileForDocumentId(documentId)
        val parentDocumentId = documentIdForFile(target.parentFile ?: rootDir())
        val deleted = deleteRecursively(target)
        if (deleted) {
            notifyParentChanged(parentDocumentId)
        }
        if (!deleted) {
            throw FileNotFoundException("failed to delete $documentId")
        }
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        val file = fileForDocumentId(documentId)
        file.parentFile?.mkdirs()
        if (!file.exists()) {
            file.createNewFile()
        }
        if (!mode.contains('w')) {
            recordReadOpen(file)
        }
        val descriptor = ParcelFileDescriptor.open(file, ParcelFileDescriptor.parseMode(mode))
        if (mode.contains('w')) {
            notifyParentChanged(parentDocumentIdForFile(file))
        }
        return descriptor
    }

    private fun includeDocument(cursor: MatrixCursor, documentId: String) {
        val file = fileForDocumentId(documentId)
        val row = cursor.newRow()
        row.add(DocumentsContract.Document.COLUMN_DOCUMENT_ID, documentId)
        row.add(DocumentsContract.Document.COLUMN_DISPLAY_NAME, if (documentId == ROOT_DOCUMENT_ID) "root" else file.name)
        row.add(
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            if (file.isDirectory) DocumentsContract.Document.MIME_TYPE_DIR else "application/octet-stream",
        )
        row.add(
            DocumentsContract.Document.COLUMN_FLAGS,
            DocumentsContract.Document.FLAG_SUPPORTS_DELETE or
                DocumentsContract.Document.FLAG_SUPPORTS_WRITE or
                if (file.isDirectory) DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE else 0,
        )
        row.add(DocumentsContract.Document.COLUMN_SIZE, if (file.isFile) file.length() else 0L)
        row.add(DocumentsContract.Document.COLUMN_LAST_MODIFIED, file.lastModified())
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

    private fun fileForDocumentId(documentId: String): File {
        return when {
            documentId == ROOT_DOCUMENT_ID -> rootDir()
            documentId.startsWith("dir:") -> File(rootDir(), documentId.removePrefix("dir:"))
            documentId.startsWith("file:") -> File(rootDir(), documentId.removePrefix("file:"))
            else -> throw FileNotFoundException("unknown document id: $documentId")
        }
    }

    private fun documentIdForFile(file: File): String {
        val canonicalRoot = rootDir().canonicalFile
        val canonicalFile = file.canonicalFile
        if (canonicalFile == canonicalRoot) {
            return ROOT_DOCUMENT_ID
        }
        val relative = canonicalFile.relativeTo(canonicalRoot).invariantSeparatorsPath
        return if (canonicalFile.isDirectory) "dir:$relative" else "file:$relative"
    }

    private fun parentDocumentIdForFile(file: File): String {
        val parent = file.parentFile ?: rootDir()
        return documentIdForFile(parent)
    }

    private fun notifyParentChanged(parentDocumentId: String) {
        val ctx = context ?: return
        val rawChildrenUri = DocumentsContract.buildChildDocumentsUri(AUTHORITY, parentDocumentId)
        val treeChildrenUri =
            DocumentsContract.buildChildDocumentsUriUsingTree(treeUri(), parentDocumentId)
        ctx.contentResolver.notifyChange(rawChildrenUri, null)
        ctx.contentResolver.notifyChange(treeChildrenUri, null)
    }

    companion object {
        const val AUTHORITY = "io.ironmesh.android.test.documents"
        private const val ROOT_ID = "test-root"
        private const val ROOT_DOCUMENT_ID = "root"

        fun treeUri() = DocumentsContract.buildTreeDocumentUri(AUTHORITY, ROOT_DOCUMENT_ID)

        fun resetRoot(context: Context) {
            val root = rootDir(context)
            if (root.exists()) {
                deleteRecursively(root)
            }
            root.mkdirs()
            openCounts.clear()
        }

        fun seedFile(context: Context, relativePath: String, bytes: ByteArray) {
            val target = File(rootDir(context), relativePath.replace('/', File.separatorChar))
            target.parentFile?.mkdirs()
            target.writeBytes(bytes)
        }

        fun resetOpenCounts() {
            openCounts.clear()
        }

        fun openCountFor(relativePath: String): Int {
            return openCounts[relativePath.replace('\\', '/')]?.get() ?: 0
        }

        private fun rootDir(context: Context): File =
            File(context.cacheDir, "test-tree-documents-provider")

        private fun rootDir(): File {
            val ctx = checkNotNull(instanceContext) { "provider context is not available" }
            return rootDir(ctx)
        }

        @Volatile
        private var instanceContext: Context? = null

        private val openCounts = ConcurrentHashMap<String, AtomicInteger>()

        private fun recordReadOpen(file: File) {
            val relativePath = file.canonicalFile
                .relativeTo(rootDir().canonicalFile)
                .invariantSeparatorsPath
            openCounts.computeIfAbsent(relativePath) { AtomicInteger() }.incrementAndGet()
        }

        private fun deleteRecursively(file: File): Boolean {
            if (!file.exists()) {
                return true
            }
            if (file.isDirectory) {
                file.listFiles()?.forEach { child ->
                    deleteRecursively(child)
                }
            }
            return file.delete()
        }
    }

    override fun attachInfo(context: Context, info: android.content.pm.ProviderInfo) {
        super.attachInfo(context, info)
        instanceContext = context.applicationContext
        rootDir(context).mkdirs()
    }
}
