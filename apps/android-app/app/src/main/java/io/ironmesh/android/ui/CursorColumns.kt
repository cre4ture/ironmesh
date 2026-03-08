package io.ironmesh.android.ui

import android.database.Cursor

internal fun Cursor.columnIndexOrNull(columnName: String): Int? {
    val exactIndex = columnNames.indexOf(columnName)
    if (exactIndex >= 0) {
        return exactIndex
    }

    val fallbackName = columnName.substringAfterLast('.', columnName)
    if (fallbackName != columnName) {
        val fallbackIndex = columnNames.indexOf(fallbackName)
        if (fallbackIndex >= 0) {
            return fallbackIndex
        }
        return getColumnIndex(fallbackName).takeIf { it >= 0 }
    }

    return getColumnIndex(columnName).takeIf { it >= 0 }
}

internal fun Cursor.stringOrNull(columnName: String): String? {
    val index = columnIndexOrNull(columnName) ?: return null
    if (isNull(index)) {
        return null
    }
    return getString(index)
}

internal fun Cursor.longOrNull(columnName: String): Long? {
    val index = columnIndexOrNull(columnName) ?: return null
    if (isNull(index)) {
        return null
    }
    return getLong(index)
}

internal fun Cursor.intOrNull(columnName: String): Int? {
    val index = columnIndexOrNull(columnName) ?: return null
    if (isNull(index)) {
        return null
    }
    return getInt(index)
}
