package io.ironmesh.android.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RustSafDocumentCacheTest {
    @Test
    fun children_reusesLoadedDirectoryListingUntilTreeInvalidation() {
        val cache = RustSafDocumentCache()
        var loads = 0
        val expected = listOf(
            RustSafChildDocument(
                documentId = "doc-1",
                displayName = "alpha.txt",
                mimeType = "text/plain",
                sizeBytes = 12,
                modifiedUnixMs = 99,
            ),
        )

        val first = cache.children("tree-a", "parent-1") {
            loads += 1
            expected
        }
        val second = cache.children("tree-a", "parent-1") {
            loads += 1
            emptyList()
        }

        assertEquals(1, loads)
        assertEquals(expected, first)
        assertEquals(expected, second)

        cache.invalidateTree("tree-a")

        val third = cache.children("tree-a", "parent-1") {
            loads += 1
            emptyList()
        }
        assertEquals(2, loads)
        assertEquals(emptyList<RustSafChildDocument>(), third)
    }

    @Test
    fun cachedDocument_isScopedPerTreeAndDroppedByInvalidation() {
        val cache = RustSafDocumentCache()
        val treeADocument = RustSafChildDocument(
            documentId = "doc-a",
            displayName = "notes.txt",
            mimeType = "text/plain",
            sizeBytes = 7,
            modifiedUnixMs = 10,
        )
        val treeBDocument = RustSafChildDocument(
            documentId = "doc-b",
            displayName = "notes.txt",
            mimeType = "text/plain",
            sizeBytes = 11,
            modifiedUnixMs = 20,
        )

        cache.recordDocument("tree-a", "notes.txt", treeADocument)
        cache.recordDocument("tree-b", "notes.txt", treeBDocument)

        assertEquals(treeADocument, cache.cachedDocument("tree-a", "notes.txt"))
        assertEquals(treeBDocument, cache.cachedDocument("tree-b", "notes.txt"))

        cache.invalidateTree("tree-a")

        assertNull(cache.cachedDocument("tree-a", "notes.txt"))
        assertEquals(treeBDocument, cache.cachedDocument("tree-b", "notes.txt"))
    }
}
