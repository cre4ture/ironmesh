package io.ironmesh.android

import android.graphics.Bitmap
import android.graphics.Color
import android.os.Build
import android.provider.DocumentsContract
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.ironmesh.android.data.TestTreeDocumentsProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream

@RunWith(AndroidJUnit4::class)
class DocumentBitmapLoaderInstrumentationTest {
    private val appContext by lazy { ApplicationProvider.getApplicationContext<android.content.Context>() }

    @Before
    fun setUp() {
        TestTreeDocumentsProvider.resetRoot(appContext)
        TestTreeDocumentsProvider.resetOpenCounts()
    }

    @Test
    fun decodeWithImageDecoder_decodesProviderImageAtRequestedScale() {
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)

        TestTreeDocumentsProvider.seedFile(appContext, "images/decoder.png", createPngBytes(64, 32))

        val bitmap = DocumentBitmapLoader.decodeWithImageDecoder(
            contentResolver = appContext.contentResolver,
            documentUri = documentUriFor("images/decoder.png"),
            maxDimensionPx = 16,
        )

        assertEquals(16, bitmap.width)
        assertEquals(8, bitmap.height)
    }

    @Test
    fun decodeWithBitmapFactory_readsProviderStreamOnceAndDecodesImage() {
        TestTreeDocumentsProvider.seedFile(appContext, "images/fallback.png", createPngBytes(64, 32))

        val bitmap = DocumentBitmapLoader.decodeWithBitmapFactory(
            context = appContext,
            contentResolver = appContext.contentResolver,
            documentUri = documentUriFor("images/fallback.png"),
            maxDimensionPx = 16,
        )

        assertEquals(16, bitmap.width)
        assertEquals(8, bitmap.height)
        assertEquals(1, TestTreeDocumentsProvider.openCountFor("images/fallback.png"))
    }

    @Test
    fun load_returnsNullWhenProviderDataIsNotAnImage() {
        TestTreeDocumentsProvider.seedFile(appContext, "broken/not-image.bin", byteArrayOf(1, 2, 3, 4))

        val bitmap = DocumentBitmapLoader.load(
            context = appContext,
            contentResolver = appContext.contentResolver,
            documentUri = documentUriFor("broken/not-image.bin"),
            maxDimensionPx = 128,
        )

        assertNull(bitmap)
    }

    private fun documentUriFor(relativePath: String) =
        DocumentsContract.buildDocumentUri(
            TestTreeDocumentsProvider.AUTHORITY,
            "file:${relativePath.replace('\\', '/')}",
        )

    private fun createPngBytes(width: Int, height: Int): ByteArray {
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(Color.rgb(24, 92, 180))
        return ByteArrayOutputStream().use { output ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)
            output.toByteArray()
        }
    }
}
