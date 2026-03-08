package io.ironmesh.android.saf

import android.database.MatrixCursor
import android.provider.DocumentsContract
import io.ironmesh.android.api.StoreIndexEntry

internal object IronmeshCursorRows {
    fun populateRootRow(
        cursor: MatrixCursor,
        row: MatrixCursor.RowBuilder,
        rootId: String,
        documentId: String,
        title: String,
        summary: String,
        flags: Int,
        mimeTypes: String,
        icon: Int,
    ) {
        addColumnIfPresent(cursor, row, DocumentsContract.Root.COLUMN_ROOT_ID, rootId)
        addColumnIfPresent(cursor, row, DocumentsContract.Root.COLUMN_DOCUMENT_ID, documentId)
        addColumnIfPresent(cursor, row, DocumentsContract.Root.COLUMN_TITLE, title)
        addColumnIfPresent(cursor, row, DocumentsContract.Root.COLUMN_SUMMARY, summary)
        addColumnIfPresent(cursor, row, DocumentsContract.Root.COLUMN_FLAGS, flags)
        addColumnIfPresent(cursor, row, DocumentsContract.Root.COLUMN_MIME_TYPES, mimeTypes)
        addColumnIfPresent(cursor, row, DocumentsContract.Root.COLUMN_ICON, icon)
    }

    fun populateDirectoryRow(
        cursor: MatrixCursor,
        row: MatrixCursor.RowBuilder,
        documentId: String,
        name: String,
    ) {
        addColumnIfPresent(cursor, row, DocumentsContract.Document.COLUMN_DOCUMENT_ID, documentId)
        addColumnIfPresent(cursor, row, DocumentsContract.Document.COLUMN_DISPLAY_NAME, name)
        addColumnIfPresent(
            cursor,
            row,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.MIME_TYPE_DIR,
        )
        addColumnIfPresent(
            cursor,
            row,
            DocumentsContract.Document.COLUMN_FLAGS,
            DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE,
        )
    }

    fun populateFileRow(
        cursor: MatrixCursor,
        row: MatrixCursor.RowBuilder,
        documentId: String,
        entry: StoreIndexEntry,
        fallbackMimeType: String,
        summary: String?,
    ) {
        val fullPath = entry.path
        val fileName = fullPath.substringAfterLast('/')
        val mime = entry.media?.mime_type ?: fallbackMimeType
        val createdAtMillis = entry.media?.taken_at_unix?.times(1000)
        val thumbnail = entry.media?.thumbnail

        addColumnIfPresent(cursor, row, DocumentsContract.Document.COLUMN_DOCUMENT_ID, documentId)
        addColumnIfPresent(cursor, row, DocumentsContract.Document.COLUMN_DISPLAY_NAME, fileName)
        addColumnIfPresent(cursor, row, DocumentsContract.Document.COLUMN_MIME_TYPE, mime)
        addColumnIfPresent(
            cursor,
            row,
            DocumentsContract.Document.COLUMN_FLAGS,
            DocumentsContract.Document.FLAG_SUPPORTS_WRITE or
                if (thumbnail != null) DocumentsContract.Document.FLAG_SUPPORTS_THUMBNAIL else 0,
        )
        addColumnIfPresent(
            cursor,
            row,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            createdAtMillis,
        )
        addColumnIfPresent(cursor, row, DocumentsContract.Document.COLUMN_SUMMARY, summary)
        addColumnIfPresent(cursor, row, IronmeshDocumentColumns.COLUMN_REMOTE_PATH, fullPath)
        addColumnIfPresent(
            cursor,
            row,
            IronmeshDocumentColumns.COLUMN_CREATED_AT_UNIX_MS,
            createdAtMillis,
        )
        addColumnIfPresent(cursor, row, IronmeshDocumentColumns.COLUMN_IMAGE_WIDTH, entry.media?.width)
        addColumnIfPresent(
            cursor,
            row,
            IronmeshDocumentColumns.COLUMN_IMAGE_HEIGHT,
            entry.media?.height,
        )
        addColumnIfPresent(
            cursor,
            row,
            IronmeshDocumentColumns.COLUMN_THUMBNAIL_STATUS,
            entry.media?.status,
        )
        addColumnIfPresent(
            cursor,
            row,
            IronmeshDocumentColumns.COLUMN_THUMBNAIL_WIDTH,
            thumbnail?.width,
        )
        addColumnIfPresent(
            cursor,
            row,
            IronmeshDocumentColumns.COLUMN_THUMBNAIL_HEIGHT,
            thumbnail?.height,
        )
    }

    private fun addColumnIfPresent(
        cursor: MatrixCursor,
        row: MatrixCursor.RowBuilder,
        columnName: String,
        value: Any?,
    ) {
        if (cursor.columnNames.contains(columnName)) {
            row.add(columnName, value)
        }
    }
}
