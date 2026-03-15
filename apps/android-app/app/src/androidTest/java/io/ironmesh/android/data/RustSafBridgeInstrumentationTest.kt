package io.ironmesh.android.data

import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONArray
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RustSafBridgeInstrumentationTest {
    private val appContext by lazy { ApplicationProvider.getApplicationContext<android.content.Context>() }
    private val treeUriString by lazy { TestTreeDocumentsProvider.treeUri().toString() }

    @Before
    fun setUp() {
        TestTreeDocumentsProvider.resetRoot(appContext)
        RustSafBridge.initialize(appContext)
    }

    @Test
    fun listTreeSnapshot_andFileRoundTrip_workAgainstDocumentsProvider() {
        TestTreeDocumentsProvider.seedFile(appContext, "seed/hello.txt", "hello".toByteArray())
        TestTreeDocumentsProvider.seedFile(appContext, ".thumbnails/skip.jpg", byteArrayOf(1, 2, 3))

        val initialPaths = snapshotPaths(RustSafBridge.listTreeSnapshot(treeUriString))
        assertTrue(initialPaths.contains("seed"))
        assertTrue(initialPaths.contains("seed/hello.txt"))
        assertFalse(initialPaths.contains(".thumbnails"))
        assertFalse(initialPaths.contains(".thumbnails/skip.jpg"))

        RustSafBridge.ensureTreeDirectory(treeUriString, "nested/camera")
        RustSafBridge.openTreeFileOutput(treeUriString, "nested/camera/new.txt").use { output ->
            output.write("from-test".toByteArray())
        }

        val bytes = RustSafBridge.openTreeFileInput(treeUriString, "nested/camera/new.txt").use { input ->
            input.readBytes()
        }
        assertArrayEquals("from-test".toByteArray(), bytes)

        val afterWritePaths = snapshotPaths(RustSafBridge.listTreeSnapshot(treeUriString))
        assertTrue(afterWritePaths.contains("nested"))
        assertTrue(afterWritePaths.contains("nested/camera"))
        assertTrue(afterWritePaths.contains("nested/camera/new.txt"))

        assertTrue(RustSafBridge.deleteTreePath(treeUriString, "nested/camera/new.txt"))
        val afterDeletePaths = snapshotPaths(RustSafBridge.listTreeSnapshot(treeUriString))
        assertFalse(afterDeletePaths.contains("nested/camera/new.txt"))
    }

    @Test
    fun contentObserverVersion_incrementsAfterTreeMutation() {
        RustSafBridge.prepareTreeObserver(treeUriString)
        try {
            RustSafBridge.listTreeSnapshot(treeUriString)
            val before = RustSafBridge.getTreeChangeVersion(treeUriString)

            RustSafBridge.openTreeFileOutput(treeUriString, "observer/new-file.txt").use { output ->
                output.write("observer".toByteArray())
            }

            assertTrue(waitForTreeVersionGreaterThan(before))
        } finally {
            RustSafBridge.releaseTreeObserver(treeUriString)
        }
    }

    private fun snapshotPaths(snapshotJson: String): Set<String> {
        val array = JSONArray(snapshotJson)
        val result = linkedSetOf<String>()
        for (index in 0 until array.length()) {
            result += array.getJSONObject(index).getString("path")
        }
        return result
    }

    private fun waitForTreeVersionGreaterThan(previous: Long, timeoutMs: Long = 5_000): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (SystemClock.elapsedRealtime() < deadline) {
            if (RustSafBridge.getTreeChangeVersion(treeUriString) > previous) {
                return true
            }
            SystemClock.sleep(100)
        }
        return false
    }
}
