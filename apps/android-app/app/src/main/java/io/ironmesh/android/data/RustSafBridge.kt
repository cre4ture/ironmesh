package io.ironmesh.android.data

import android.content.ContentResolver
import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.webkit.MimeTypeMap
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicLong

object RustSafBridge {
    @Volatile
    private var appContext: Context? = null
    private val observerLock = Any()
    private val treeObservers = mutableMapOf<String, TreeObserverState>()

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
        val observedChildrenUris = linkedSetOf<Uri>()
        collectEntries(
            resolver = resolver,
            treeUri = treeUri,
            parentDocumentId = rootDocumentId,
            prefix = "",
            visitedDocumentIds = mutableSetOf(),
            observedChildrenUris = observedChildrenUris,
            output = entries,
        )
        updateObservedChildrenUris(treeUriString, observedChildrenUris)
        return entries.toString()
    }

    @JvmStatic
    fun prepareTreeObserver(treeUriString: String) {
        val resolver = requireResolver()
        synchronized(observerLock) {
            treeObservers.getOrPut(treeUriString) {
                TreeObserverState(treeUriString, resolver)
            }
        }
    }

    @JvmStatic
    fun releaseTreeObserver(treeUriString: String) {
        synchronized(observerLock) {
            treeObservers.remove(treeUriString)?.close()
        }
    }

    @JvmStatic
    fun getTreeChangeVersion(treeUriString: String): Long {
        synchronized(observerLock) {
            return treeObservers[treeUriString]?.version?.get() ?: 0L
        }
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
        observedChildrenUris: MutableSet<Uri>,
        output: JSONArray,
    ) {
        if (!visitedDocumentIds.add(parentDocumentId)) {
            return
        }

        observedChildrenUris += DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentDocumentId)

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
                    observedChildrenUris = observedChildrenUris,
                    output = output,
                )
            }
        }
    }

    private fun updateObservedChildrenUris(
        treeUriString: String,
        observedChildrenUris: Set<Uri>,
    ) {
        synchronized(observerLock) {
            val state = treeObservers[treeUriString] ?: return
            state.updateObservedChildrenUris(observedChildrenUris)
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
        return RustSafBridgePaths.normalizeRelativePath(relativePath)
    }

    private fun shouldIgnorePath(relativePath: String): Boolean {
        return RustSafBridgePaths.shouldIgnorePath(relativePath)
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

    private class TreeObserverState(
        private val treeUriString: String,
        private val resolver: ContentResolver,
    ) {
        val version = AtomicLong(0L)
        private val handler = Handler(Looper.getMainLooper())
        private val observers = linkedMapOf<String, ContentObserver>()

        fun updateObservedChildrenUris(childrenUris: Set<Uri>) {
            val desired = childrenUris.map(Uri::toString).toSet()

            val toRemove = observers.keys.filterNot { it in desired }
            for (uriString in toRemove) {
                observers.remove(uriString)?.let(resolver::unregisterContentObserver)
            }

            for (uri in childrenUris) {
                val uriString = uri.toString()
                if (observers.containsKey(uriString)) {
                    continue
                }
                val observer = object : ContentObserver(handler) {
                    override fun onChange(selfChange: Boolean) {
                        version.incrementAndGet()
                    }

                    override fun onChange(selfChange: Boolean, uri: Uri?) {
                        version.incrementAndGet()
                    }
                }
                resolver.registerContentObserver(uri, false, observer)
                observers[uriString] = observer
            }
        }

        fun close() {
            for (observer in observers.values) {
                resolver.unregisterContentObserver(observer)
            }
            observers.clear()
        }
    }
}
