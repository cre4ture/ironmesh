package io.ironmesh.android.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

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

    @Test
    fun children_doesNotRepopulateCacheWithStaleListingAfterInvalidation() {
        val cache = RustSafDocumentCache()
        val loaderStarted = CountDownLatch(1)
        val resumeLoader = CountDownLatch(1)
        val staleResult = AtomicReference<List<RustSafChildDocument>>()
        val staleListing = listOf(
            RustSafChildDocument(
                documentId = "doc-stale",
                displayName = "stale.txt",
                mimeType = "text/plain",
                sizeBytes = 3,
                modifiedUnixMs = 7,
            ),
        )

        val worker = Thread {
            staleResult.set(
                cache.children("tree-a", "parent-1") {
                    loaderStarted.countDown()
                    check(resumeLoader.await(5, TimeUnit.SECONDS)) {
                        "timed out waiting to resume stale loader"
                    }
                    staleListing
                }
            )
        }
        worker.start()

        check(loaderStarted.await(5, TimeUnit.SECONDS)) {
            "timed out waiting for stale loader to start"
        }
        cache.invalidateTree("tree-a")
        resumeLoader.countDown()
        worker.join(5_000)
        check(!worker.isAlive) { "stale loader worker did not finish" }

        val reloaded = cache.children("tree-a", "parent-1") {
            emptyList()
        }

        assertEquals(staleListing, staleResult.get())
        assertEquals(emptyList<RustSafChildDocument>(), reloaded)
    }
}
