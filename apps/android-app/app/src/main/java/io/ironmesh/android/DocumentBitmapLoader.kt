package io.ironmesh.android

import android.content.ContentResolver
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Build
import android.util.Log
import java.io.File

object DocumentBitmapLoader {
    fun load(
        context: Context,
        contentResolver: ContentResolver,
        documentUri: Uri,
        maxDimensionPx: Int,
    ): Bitmap? {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                decodeWithImageDecoder(contentResolver, documentUri, maxDimensionPx)
            } else {
                decodeWithBitmapFactory(
                    context = context,
                    contentResolver = contentResolver,
                    documentUri = documentUri,
                    maxDimensionPx = maxDimensionPx,
                )
            }
        }.onFailure { error ->
            Log.w("MainActivity", "Full image load failed for $documentUri", error)
        }.getOrNull()
    }

    fun decodeWithImageDecoder(
        contentResolver: ContentResolver,
        documentUri: Uri,
        maxDimensionPx: Int,
    ): Bitmap {
        val source = ImageDecoder.createSource(contentResolver, documentUri)
        return ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
            val sampleSize = computeInSampleSize(
                width = info.size.width,
                height = info.size.height,
                maxDimensionPx = maxDimensionPx,
            )
            decoder.setAllocator(ImageDecoder.ALLOCATOR_SOFTWARE)
            if (sampleSize > 1) {
                decoder.setTargetSize(
                    (info.size.width / sampleSize).coerceAtLeast(1),
                    (info.size.height / sampleSize).coerceAtLeast(1),
                )
            }
        }
    }

    fun decodeWithBitmapFactory(
        context: Context,
        contentResolver: ContentResolver,
        documentUri: Uri,
        maxDimensionPx: Int,
    ): Bitmap {
        val stagedFile = File.createTempFile("ironmesh-viewer-", ".img", context.cacheDir)
        try {
            val inputStream = contentResolver.openInputStream(documentUri)
                ?: error("Failed to open image stream")
            inputStream.use { input ->
                stagedFile.outputStream().use { output ->
                    input.copyTo(output)
                    output.flush()
                }
            }

            val bounds = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            BitmapFactory.decodeFile(stagedFile.absolutePath, bounds)

            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
                error("Failed to decode image bounds")
            }

            val sampleSize = computeInSampleSize(
                width = bounds.outWidth,
                height = bounds.outHeight,
                maxDimensionPx = maxDimensionPx,
            )
            val decodeOptions = BitmapFactory.Options().apply {
                inSampleSize = sampleSize
            }
            val bitmap = BitmapFactory.decodeFile(stagedFile.absolutePath, decodeOptions)
            return bitmap ?: error("Bitmap decode returned null")
        } finally {
            stagedFile.delete()
        }
    }

    private fun computeInSampleSize(
        width: Int,
        height: Int,
        maxDimensionPx: Int,
    ): Int {
        if (width <= 0 || height <= 0 || maxDimensionPx <= 0) {
            return 1
        }

        var sampleSize = 1
        while (width / sampleSize > maxDimensionPx || height / sampleSize > maxDimensionPx) {
            sampleSize *= 2
        }
        return sampleSize.coerceAtLeast(1)
    }
}
