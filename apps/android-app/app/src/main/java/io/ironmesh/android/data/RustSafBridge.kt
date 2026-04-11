package io.ironmesh.android.data

import android.Manifest
import android.content.ContentResolver
import android.content.ContentUris
import android.content.Context
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.util.Log
import android.webkit.MimeTypeMap
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicLong

object RustSafBridge {
    private const val TAG = "RustSafBridge"

    @Volatile
    private var appContext: Context? = null
    private val observerLock = Any()
    private val scanProgressLock = Any()
    private val treeObservers = mutableMapOf<String, TreeObserverState>()
    private val treeScanProgress = mutableMapOf<String, TreeScanProgressState>()

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
        beginTreeScanProgress(treeUriString)
        try {
            collectEntries(
                resolver = resolver,
                treeUriString = treeUriString,
                treeUri = treeUri,
                parentDocumentId = rootDocumentId,
                prefix = "",
                visitedDocumentIds = mutableSetOf(),
                observedChildrenUris = observedChildrenUris,
                output = entries,
            )
        } finally {
            finishTreeScanProgress(treeUriString)
        }
        updateObservedChildrenUris(treeUriString, observedChildrenUris)
        return entries.toString()
    }

    @JvmStatic
    fun getTreeScanProgress(treeUriString: String): String? {
        synchronized(scanProgressLock) {
            return treeScanProgress[treeUriString]?.toJson()?.toString()
        }
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
        val preferredStream = tryOpenOriginalPhotoInput(
            resolver = resolver,
            treeUri = treeUri,
            relativePath = relativePath,
            documentUri = documentUri,
        )
        if (preferredStream != null) {
            return preferredStream
        }

        return resolver.openInputStream(documentUri)
            ?.also {
                Log.i(TAG, "Using SAF stream for $relativePath")
            }
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

    private fun tryOpenOriginalPhotoInput(
        resolver: ContentResolver,
        treeUri: Uri,
        relativePath: String,
        documentUri: Uri,
    ): InputStream? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return null
        }

        val context = appContext ?: return null
        val mimeType = resolver.getType(documentUri) ?: guessMimeType(relativePath)
        if (!mimeType.startsWith("image/")) {
            return null
        }

        if (!hasPermission(context, Manifest.permission.ACCESS_MEDIA_LOCATION)) {
            Log.i(TAG, "Using SAF image stream for $relativePath because ACCESS_MEDIA_LOCATION is not granted")
            return null
        }

        val imageReadPermission = imageReadPermission()
        if (imageReadPermission != null && !hasPermission(context, imageReadPermission)) {
            Log.i(TAG, "Using SAF image stream for $relativePath because $imageReadPermission is not granted")
            return null
        }

        val lookup = resolveMediaStoreImageLookup(treeUri, relativePath)
        if (lookup == null) {
            Log.i(TAG, "Using SAF image stream for $relativePath because no MediaStore lookup path was available")
            return null
        }

        val mediaUri = resolveMediaStoreImageUri(resolver, lookup)
        if (mediaUri == null) {
            Log.i(
                TAG,
                "Using SAF image stream for $relativePath because MediaStore had no matching image for ${lookup.relativePath}${lookup.displayName}",
            )
            return null
        }

        val originalUri = runCatching { MediaStore.setRequireOriginal(mediaUri) }
            .onFailure { error ->
                Log.i(
                    TAG,
                    "Using SAF image stream for $relativePath because original MediaStore URI failed: ${error.message}",
                )
            }
            .getOrNull()
            ?: return null

        return runCatching {
            resolver.openInputStream(originalUri)
        }.onFailure { error ->
            Log.i(
                TAG,
                "Using SAF image stream for $relativePath because opening original photo bytes failed: ${error.message}",
            )
        }.getOrNull()?.also {
            Log.i(TAG, "Using original MediaStore bytes for $relativePath via $mediaUri")
        }
    }

    private fun hasPermission(context: Context, permission: String): Boolean {
        return ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun imageReadPermission(): String? {
        return when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> Manifest.permission.READ_MEDIA_IMAGES
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M -> Manifest.permission.READ_EXTERNAL_STORAGE
            else -> null
        }
    }

    private fun resolveMediaStoreImageUri(
        resolver: ContentResolver,
        lookup: MediaStoreImageLookup,
    ): Uri? {
        val collections = linkedSetOf(
            MediaStore.Images.Media.getContentUri(lookup.volumeName),
            MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL),
        )

        for (collection in collections) {
            val result = queryMediaStoreImageUri(resolver, collection, lookup)
            if (result != null) {
                return result
            }
        }

        return null
    }

    private fun queryMediaStoreImageUri(
        resolver: ContentResolver,
        collection: Uri,
        lookup: MediaStoreImageLookup,
    ): Uri? {
        val projection = arrayOf(MediaStore.Images.Media._ID)
        val selection: String
        val selectionArgs: Array<String>
        if (lookup.relativePath.isBlank()) {
            selection = "${MediaStore.Images.Media.DISPLAY_NAME} = ?"
            selectionArgs = arrayOf(lookup.displayName)
        } else {
            selection =
                "${MediaStore.Images.Media.DISPLAY_NAME} = ? AND ${MediaStore.Images.Media.RELATIVE_PATH} = ?"
            selectionArgs = arrayOf(lookup.displayName, lookup.relativePath)
        }

        return runCatching {
            resolver.query(collection, projection, selection, selectionArgs, null)?.use { cursor ->
                val idIndex = cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
                if (!cursor.moveToFirst()) {
                    return@use null
                }

                val id = cursor.getLong(idIndex)
                ContentUris.withAppendedId(collection, id)
            }
        }.getOrNull()
    }

    private fun resolveMediaStoreImageLookup(
        treeUri: Uri,
        relativePath: String,
    ): MediaStoreImageLookup? {
        val absolutePath = resolveTreeFilePath(treeUri, relativePath) ?: return null
        val normalized = absolutePath.replace('\\', '/')

        val (volumeName, relativeWithinVolume) = when {
            normalized.startsWith("/storage/emulated/0/") -> {
                MediaStore.VOLUME_EXTERNAL_PRIMARY to normalized.removePrefix("/storage/emulated/0/")
            }
            normalized.startsWith("/storage/") -> {
                val suffix = normalized.removePrefix("/storage/")
                val volume = suffix.substringBefore('/', "")
                if (volume.length != 9 || volume[4] != '-') {
                    return null
                }
                volume to suffix.substringAfter('/', "")
            }
            else -> return null
        }

        if (relativeWithinVolume.isBlank()) {
            return null
        }

        val displayName = relativeWithinVolume.substringAfterLast('/')
        val parent = relativeWithinVolume.substringBeforeLast('/', "")
        val mediaRelativePath = if (parent.isBlank()) "" else "$parent/"
        return MediaStoreImageLookup(
            volumeName = volumeName,
            relativePath = mediaRelativePath,
            displayName = displayName,
        )
    }

    private fun resolveTreeFilePath(treeUri: Uri, relativePath: String): String? {
        val rootPath = resolveTreeUriToFilesystemPath(treeUri) ?: return null
        val normalizedRelativePath = normalizeRelativePath(relativePath)
        if (normalizedRelativePath.isBlank()) {
            return rootPath
        }

        return buildString {
            append(rootPath.trimEnd('/'))
            normalizedRelativePath.split('/').forEach { segment ->
                append('/')
                append(segment)
            }
        }
    }

    private fun resolveTreeUriToFilesystemPath(treeUri: Uri): String? {
        val documentId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull()
            ?: return null
        if (documentId.startsWith("raw:")) {
            return documentId.removePrefix("raw:")
        }

        val storageRoot = documentId.substringBefore(':', "")
        val relative = documentId.substringAfter(':', "")
            .split('/')
            .filter { it.isNotBlank() }

        val basePath = when {
            storageRoot.equals("primary", ignoreCase = true) -> "/storage/emulated/0"
            storageRoot.equals("home", ignoreCase = true) -> "/storage/emulated/0/Documents"
            storageRoot.length == 9 && storageRoot[4] == '-' -> "/storage/$storageRoot"
            else -> return null
        }

        return if (relative.isEmpty()) {
            basePath
        } else {
            buildString {
                append(basePath.trimEnd('/'))
                relative.forEach { segment ->
                    append('/')
                    append(segment)
                }
            }
        }
    }

    private data class MediaStoreImageLookup(
        val volumeName: String,
        val relativePath: String,
        val displayName: String,
    )

    private fun collectEntries(
        resolver: ContentResolver,
        treeUriString: String,
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

        enterTreeScanDirectory(
            treeUriString = treeUriString,
            currentPath = if (prefix.isBlank()) "<root>" else prefix,
        )

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

             recordTreeScanEntry(
                treeUriString = treeUriString,
                currentPath = relativePath,
                discoveredDirectory = child.isDirectory,
            )

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
                    treeUriString = treeUriString,
                    treeUri = treeUri,
                    parentDocumentId = child.documentId,
                    prefix = relativePath,
                    visitedDocumentIds = visitedDocumentIds,
                    observedChildrenUris = observedChildrenUris,
                    output = output,
                )
            }
        }

        completeTreeScanDirectory(treeUriString)
    }

    private fun beginTreeScanProgress(treeUriString: String) {
        synchronized(scanProgressLock) {
            treeScanProgress[treeUriString] = TreeScanProgressState(
                pendingDirectoryCount = 1L,
                currentPath = "<root>",
            )
        }
    }

    private fun enterTreeScanDirectory(
        treeUriString: String,
        currentPath: String,
    ) {
        synchronized(scanProgressLock) {
            val state = treeScanProgress[treeUriString] ?: return
            state.scannedDirectoryCount += 1L
            state.currentPath = currentPath
        }
    }

    private fun recordTreeScanEntry(
        treeUriString: String,
        currentPath: String,
        discoveredDirectory: Boolean,
    ) {
        synchronized(scanProgressLock) {
            val state = treeScanProgress[treeUriString] ?: return
            state.scannedEntryCount += 1L
            state.currentPath = currentPath
            if (discoveredDirectory) {
                state.pendingDirectoryCount += 1L
            }
        }
    }

    private fun completeTreeScanDirectory(treeUriString: String) {
        synchronized(scanProgressLock) {
            val state = treeScanProgress[treeUriString] ?: return
            state.pendingDirectoryCount = (state.pendingDirectoryCount - 1L).coerceAtLeast(0L)
        }
    }

    private fun finishTreeScanProgress(treeUriString: String) {
        synchronized(scanProgressLock) {
            treeScanProgress.remove(treeUriString)
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

    private data class TreeScanProgressState(
        var scannedEntryCount: Long = 0L,
        var scannedDirectoryCount: Long = 0L,
        var pendingDirectoryCount: Long = 0L,
        var currentPath: String? = null,
    ) {
        fun toJson(): JSONObject {
            return JSONObject()
                .put("scannedEntryCount", scannedEntryCount)
                .put("scannedDirectoryCount", scannedDirectoryCount)
                .put("pendingDirectoryCount", pendingDirectoryCount)
                .put("currentPath", currentPath)
        }
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
