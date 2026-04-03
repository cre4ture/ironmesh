package io.ironmesh.android.saf

import io.ironmesh.android.api.StoreIndexEntry
import io.ironmesh.android.data.IronmeshRepository
import java.io.FileNotFoundException
import java.io.OutputStream
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

internal interface IronmeshThumbnailStreamDataSource {
    suspend fun streamRelativeUrlTo(
        connectionInput: String,
        relativeUrl: String,
        output: OutputStream,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    )
}

internal class IronmeshRepositoryThumbnailDataSource(
    private val repository: IronmeshRepository,
) : IronmeshThumbnailStreamDataSource {
    override suspend fun streamRelativeUrlTo(
        connectionInput: String,
        relativeUrl: String,
        output: OutputStream,
        serverCaPem: String?,
        clientIdentityJson: String?,
    ) {
        repository.streamRelativeUrlTo(
            connectionInput,
            relativeUrl,
            output,
            serverCaPem,
            clientIdentityJson,
        )
    }
}

internal class IronmeshThumbnailStreamer(
    private val dataSource: IronmeshThumbnailStreamDataSource,
) {
    suspend fun streamTo(
        connectionInput: String,
        entry: StoreIndexEntry,
        output: OutputStream,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ) {
        val thumbnailUrl = entry.media?.thumbnail?.url?.trim()?.takeIf { it.isNotEmpty() }
            ?: buildGeneratedThumbnailUrl(entry)
        dataSource.streamRelativeUrlTo(
            connectionInput,
            thumbnailUrl,
            output,
            serverCaPem,
            clientIdentityJson,
        )
    }

    private fun buildGeneratedThumbnailUrl(entry: StoreIndexEntry): String {
        if (!supportsGeneratedThumbnail(entry)) {
            throw FileNotFoundException("thumbnail not available")
        }

        val encodedKey = URLEncoder.encode(entry.path, StandardCharsets.UTF_8.toString())
            .replace("+", "%20")
        return "/media/thumbnail?key=$encodedKey"
    }

    private fun supportsGeneratedThumbnail(entry: StoreIndexEntry): Boolean {
        val mimeType = entry.media?.mime_type?.lowercase()
        if (mimeType?.startsWith("image/") == true || mimeType?.startsWith("video/") == true) {
            return true
        }

        val mediaType = entry.media?.media_type?.lowercase()
        if (mediaType == "image" || mediaType == "video") {
            return true
        }

        val extension = entry.path.substringAfterLast('.', "").lowercase()
        return extension in THUMBNAIL_IMAGE_EXTENSIONS || extension in THUMBNAIL_VIDEO_EXTENSIONS
    }

    private companion object {
        val THUMBNAIL_IMAGE_EXTENSIONS = setOf(
            "avif",
            "bmp",
            "gif",
            "heic",
            "heif",
            "jpeg",
            "jpg",
            "png",
            "webp",
        )
        val THUMBNAIL_VIDEO_EXTENSIONS = setOf(
            "m4v",
            "mkv",
            "mov",
            "mp4",
            "ogv",
            "webm",
        )
    }
}
