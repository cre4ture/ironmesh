package io.ironmesh.android.ui

import android.database.MatrixCursor
import android.provider.DocumentsContract
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.ironmesh.android.saf.IronmeshDocumentColumns
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CursorColumnsTest {
    @Test
    fun dottedCustomColumnName_resolvesByExactMatch() {
        val cursor = MatrixCursor(
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                IronmeshDocumentColumns.COLUMN_REMOTE_PATH,
                IronmeshDocumentColumns.COLUMN_IMAGE_WIDTH,
            ),
        )
        cursor.addRow(arrayOf("file:gallery/cat.png", "gallery/cat.png", 640))

        cursor.moveToFirst()

        assertEquals("gallery/cat.png", cursor.stringOrNull(IronmeshDocumentColumns.COLUMN_REMOTE_PATH))
        assertEquals(640, cursor.intOrNull(IronmeshDocumentColumns.COLUMN_IMAGE_WIDTH))
    }

    @Test
    fun missingColumn_returnsNull() {
        val cursor = MatrixCursor(arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID))
        cursor.addRow(arrayOf("file:gallery/cat.png"))

        cursor.moveToFirst()

        assertNull(cursor.stringOrNull(IronmeshDocumentColumns.COLUMN_THUMBNAIL_STATUS))
    }
}
