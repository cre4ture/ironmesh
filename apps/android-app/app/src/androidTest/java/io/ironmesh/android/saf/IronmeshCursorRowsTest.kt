package io.ironmesh.android.saf

import android.database.MatrixCursor
import android.provider.DocumentsContract
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.ironmesh.android.api.StoreIndexEntry
import io.ironmesh.android.api.StoreIndexMedia
import io.ironmesh.android.api.StoreIndexThumbnail
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IronmeshCursorRowsTest {
    @Test
    fun populateFileRow_ignoresCustomColumnsWhenProjectionOmitsThem() {
        val cursor = MatrixCursor(
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_FLAGS,
            ),
        )

        val row = cursor.newRow()
        IronmeshCursorRows.populateFileRow(
            cursor = cursor,
            row = row,
            documentId = "file:gallery/cat.png",
            entry = sampleImageEntry(),
            fallbackMimeType = "image/png",
            summary = "4 x 3 - ready",
        )

        assertTrue(cursor.moveToFirst())
        assertEquals("file:gallery/cat.png", cursor.getString(0))
        assertEquals("cat.png", cursor.getString(1))
        assertEquals("image/png", cursor.getString(2))
        assertTrue(cursor.getInt(3) and DocumentsContract.Document.FLAG_SUPPORTS_WRITE != 0)
        assertTrue(
            cursor.getInt(3) and DocumentsContract.Document.FLAG_SUPPORTS_THUMBNAIL != 0,
        )
    }

    private fun sampleImageEntry(): StoreIndexEntry {
        return StoreIndexEntry(
            path = "gallery/cat.png",
            entry_type = "key",
            media = StoreIndexMedia(
                status = "ready",
                content_fingerprint = "cfp-cat",
                media_type = "image",
                mime_type = "image/png",
                width = 4,
                height = 3,
                thumbnail = StoreIndexThumbnail(
                    url = "/media/thumbnail?key=gallery%2Fcat.png",
                    profile = "grid",
                    width = 256,
                    height = 192,
                    format = "jpeg",
                    size_bytes = 1024,
                ),
            ),
        )
    }
}
