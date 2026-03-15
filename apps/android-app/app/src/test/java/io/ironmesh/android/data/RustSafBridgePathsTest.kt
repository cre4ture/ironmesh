package io.ironmesh.android.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RustSafBridgePathsTest {
    @Test
    fun normalizeRelativePath_collapsesSeparatorsAndWhitespace() {
        assertEquals(
            "Pictures/Camera/IMG_1.jpg",
            RustSafBridgePaths.normalizeRelativePath("  /Pictures\\\\Camera//IMG_1.jpg/  "),
        )
    }

    @Test
    fun normalizeRelativePath_dropsEmptySegments() {
        assertEquals(
            "alpha/beta/gamma",
            RustSafBridgePaths.normalizeRelativePath("alpha///beta//gamma"),
        )
    }

    @Test
    fun shouldIgnorePath_rejectsInternalSyncDirectories() {
        assertTrue(RustSafBridgePaths.shouldIgnorePath(".ironmesh/state.json"))
        assertTrue(RustSafBridgePaths.shouldIgnorePath("nested/.ironmesh-conflicts/file.txt"))
        assertTrue(RustSafBridgePaths.shouldIgnorePath("Pictures/.thumbnails/thumb.jpg"))
        assertTrue(RustSafBridgePaths.shouldIgnorePath("Pictures/.ironmesh-part-123.tmp"))
    }

    @Test
    fun shouldIgnorePath_keepsOrdinaryUserFiles() {
        assertFalse(RustSafBridgePaths.shouldIgnorePath(""))
        assertFalse(RustSafBridgePaths.shouldIgnorePath("Pictures/Camera/IMG_20260315_032531.jpg"))
        assertFalse(RustSafBridgePaths.shouldIgnorePath("docs/notes.txt"))
    }
}
