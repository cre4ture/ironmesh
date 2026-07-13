package io.ironmesh.android.data

import android.provider.DocumentsContract
import java.util.LinkedHashMap

internal data class RustSafChildDocument(
    val documentId: String,
    val displayName: String,
    val mimeType: String?,
    val sizeBytes: Long,
    val modifiedUnixMs: Long,
) {
    val isDirectory: Boolean
        get() = mimeType == DocumentsContract.Document.MIME_TYPE_DIR
}

internal class RustSafDocumentCache(
    private val maxCachedDocumentPaths: Int = 4_096,
    private val maxCachedChildLists: Int = 512,
) {
    private val lock = Any()
    private val trees = mutableMapOf<String, TreeCacheState>()
    private var nextTreeStateId = 1L

    fun invalidateTree(treeUriString: String) {
        synchronized(lock) {
            trees.remove(treeUriString)
        }
    }

    fun cachedDocument(
        treeUriString: String,
        relativePath: String,
    ): RustSafChildDocument? {
        synchronized(lock) {
            return trees[treeUriString]?.documentsByPath?.get(relativePath)
        }
    }

    fun recordDocument(
        treeUriString: String,
        relativePath: String,
        document: RustSafChildDocument,
    ) {
        synchronized(lock) {
            treeState(treeUriString).documentsByPath[relativePath] = document
        }
    }

    fun children(
        treeUriString: String,
        parentDocumentId: String,
        loader: () -> List<RustSafChildDocument>,
    ): List<RustSafChildDocument> {
        val expectedStateId = synchronized(lock) {
            val state = treeState(treeUriString)
            state.childrenByParentDocumentId[parentDocumentId]?.let { children ->
                return children
            }
            state.stateId
        }

        val loadedChildren = loader()

        synchronized(lock) {
            val state = trees[treeUriString]
            if (state == null || state.stateId != expectedStateId) {
                return loadedChildren.toList()
            }
            val existing = state.childrenByParentDocumentId[parentDocumentId]
            if (existing != null) {
                return existing
            }

            val cached = loadedChildren.toList()
            state.childrenByParentDocumentId[parentDocumentId] = cached
            return cached
        }
    }

    private fun treeState(treeUriString: String): TreeCacheState {
        return trees.getOrPut(treeUriString) {
            TreeCacheState(
                stateId = nextTreeStateId++,
                documentsByPath = lruMap(maxCachedDocumentPaths),
                childrenByParentDocumentId = lruMap(maxCachedChildLists),
            )
        }
    }

    private data class TreeCacheState(
        val stateId: Long,
        val documentsByPath: LinkedHashMap<String, RustSafChildDocument>,
        val childrenByParentDocumentId: LinkedHashMap<String, List<RustSafChildDocument>>,
    )
}

private fun <K, V> lruMap(maxEntries: Int): LinkedHashMap<K, V> {
    require(maxEntries > 0) { "maxEntries must be positive" }
    return object : LinkedHashMap<K, V>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?): Boolean {
            return size > maxEntries
        }
    }
}
