package io.ironmesh.android.data

internal object RustSafBridgePaths {
    fun normalizeRelativePath(relativePath: String): String {
        return relativePath
            .trim()
            .replace('\\', '/')
            .trim('/')
            .split('/')
            .filter { it.isNotBlank() }
            .joinToString("/")
    }

    fun shouldIgnorePath(relativePath: String): Boolean {
        val normalized = normalizeRelativePath(relativePath)
        if (normalized.isBlank()) {
            return false
        }
        val segments = normalized.split('/')
        return segments.any { segment ->
            segment == ".ironmesh" ||
                segment == ".ironmesh-conflicts" ||
                segment == ".thumbnails" ||
                segment.contains(".ironmesh-part-")
        }
    }
}
