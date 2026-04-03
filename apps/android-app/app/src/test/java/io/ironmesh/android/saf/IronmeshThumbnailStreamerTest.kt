package io.ironmesh.android.saf

import io.ironmesh.android.api.StoreIndexEntry
import io.ironmesh.android.api.StoreIndexMedia
import io.ironmesh.android.api.StoreIndexThumbnail
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.FileNotFoundException
import java.io.OutputStream

class IronmeshThumbnailStreamerTest {
    @Test
    fun streamTo_usesRemoteThumbnailWhenAvailable() = runBlocking {
        val dataSource = FakeThumbnailDataSource(
            thumbnailBytes = "thumb".toByteArray(),
        )
        val streamer = IronmeshThumbnailStreamer(dataSource)
        val output = ByteArrayOutputStream()

        streamer.streamTo(
            connectionInput = "https://example.invalid/",
            entry = sampleImageEntry(),
            output = output,
        )

        assertEquals(1, dataSource.relativeUrlCallCount)
        assertArrayEquals("thumb".toByteArray(), output.toByteArray())
    }

    @Test
    fun streamTo_throwsWhenThumbnailMetadataIsMissing() = runBlocking {
        val dataSource = FakeThumbnailDataSource(
            thumbnailBytes = "thumb".toByteArray(),
        )
        val streamer = IronmeshThumbnailStreamer(dataSource)
        val output = ByteArrayOutputStream()

        assertThrows(FileNotFoundException::class.java) {
            runBlocking {
                streamer.streamTo(
                    connectionInput = "{\"bootstrap\":true}",
                    entry = sampleImageEntry(thumbnail = null),
                    output = output,
                )
            }
        }
        assertEquals(0, dataSource.relativeUrlCallCount)
    }

    @Test
    fun streamTo_propagatesThumbnailFetchFailure() = runBlocking {
        val dataSource = FakeThumbnailDataSource(
            thumbnailBytes = "thumb".toByteArray(),
            relativeUrlFailure = IllegalStateException("direct endpoint unavailable"),
        )
        val streamer = IronmeshThumbnailStreamer(dataSource)
        val output = ByteArrayOutputStream()

        assertThrows(IllegalStateException::class.java) {
            runBlocking {
                streamer.streamTo(
                    connectionInput = "{\"bootstrap\":true}",
                    entry = sampleImageEntry(),
                    output = output,
                )
            }
        }
        assertEquals(1, dataSource.relativeUrlCallCount)
    }

    private fun sampleImageEntry(thumbnail: StoreIndexThumbnail? = sampleThumbnail()): StoreIndexEntry {
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
                thumbnail = thumbnail,
            ),
        )
    }

    private class FakeThumbnailDataSource(
        private val thumbnailBytes: ByteArray,
        private val relativeUrlFailure: Exception? = null,
    ) : IronmeshThumbnailStreamDataSource {
        var relativeUrlCallCount: Int = 0

        override suspend fun streamRelativeUrlTo(
            connectionInput: String,
            relativeUrl: String,
            output: OutputStream,
            serverCaPem: String?,
            clientIdentityJson: String?,
        ) {
            relativeUrlCallCount += 1
            relativeUrlFailure?.let { throw it }
            output.write(thumbnailBytes)
        }
    }

    private companion object {
        fun sampleThumbnail(): StoreIndexThumbnail {
            return StoreIndexThumbnail(
                url = "/media/thumbnail?key=gallery%2Fcat.png",
                profile = "grid",
                width = 256,
                height = 192,
                format = "jpeg",
                size_bytes = 1024,
            )
        }
    }
}
