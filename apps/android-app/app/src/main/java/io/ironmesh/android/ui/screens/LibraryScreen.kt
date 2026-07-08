package io.ironmesh.android.ui.screens

import android.content.ContentResolver
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Point
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChange
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.ironmesh.android.DocumentBitmapLoader
import io.ironmesh.android.ui.GalleryImageItem
import io.ironmesh.android.ui.GallerySortOption
import io.ironmesh.android.ui.GalleryViewMode
import io.ironmesh.android.ui.MainUiState
import io.ironmesh.android.ui.MainViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.math.abs

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun LibraryScreen(
    state: MainUiState,
    vm: MainViewModel,
) {
    var fullscreenIndex by remember(state.galleryItems, state.galleryCurrentDirectoryPath) {
        mutableStateOf<Int?>(null)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(onClick = vm::refreshGallery) {
                Text("Refresh")
            }
            FilterChip(
                selected = state.galleryMode == GalleryViewMode.FLATTENED_ALL_IMAGES,
                onClick = { vm.updateGalleryViewMode(GalleryViewMode.FLATTENED_ALL_IMAGES) },
                label = { Text("All images") },
            )
            FilterChip(
                selected = state.galleryMode == GalleryViewMode.CURRENT_DIRECTORY,
                onClick = { vm.updateGalleryViewMode(GalleryViewMode.CURRENT_DIRECTORY) },
                label = { Text("Current folder") },
            )
            FilterChip(
                selected = state.gallerySort == GallerySortOption.CREATION_TIME,
                onClick = { vm.updateGallerySort(GallerySortOption.CREATION_TIME) },
                label = { Text("Newest") },
            )
            FilterChip(
                selected = state.gallerySort == GallerySortOption.NAME,
                onClick = { vm.updateGallerySort(GallerySortOption.NAME) },
                label = { Text("Name") },
            )
        }

        if (state.galleryMode == GalleryViewMode.CURRENT_DIRECTORY) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                tonalElevation = 2.dp,
                shape = RoundedCornerShape(22.dp),
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = "Current folder: ${state.galleryCurrentDirectoryPath}",
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = vm::navigateGalleryToRoot) {
                            Text("Root")
                        }
                        OutlinedButton(
                            onClick = vm::navigateGalleryUp,
                            enabled = state.galleryBreadcrumbs.isNotEmpty(),
                        ) {
                            Text("Up")
                        }
                    }
                    if (state.galleryBreadcrumbs.isNotEmpty()) {
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            OutlinedButton(onClick = vm::navigateGalleryToRoot) {
                                Text("/")
                            }
                            state.galleryBreadcrumbs.forEachIndexed { index, breadcrumb ->
                                OutlinedButton(onClick = { vm.navigateGalleryToBreadcrumb(index) }) {
                                    Text(breadcrumb.label)
                                }
                            }
                        }
                    }
                    if (state.galleryDirectories.isNotEmpty()) {
                        Text("Folders", style = MaterialTheme.typography.titleSmall)
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            state.galleryDirectories.forEach { directory ->
                                OutlinedButton(onClick = { vm.openGalleryDirectory(directory) }) {
                                    Text(directory.displayName)
                                }
                            }
                        }
                    }
                }
            }
        }

        when {
            state.galleryLoading -> CircularProgressIndicator()
            state.galleryItems.isEmpty() && state.galleryDirectories.isEmpty() -> Text(
                if (state.galleryMode == GalleryViewMode.FLATTENED_ALL_IMAGES) {
                    "No images loaded from the document provider."
                } else {
                    "No images or nested folders found in the current directory."
                },
            )
            state.galleryItems.isEmpty() -> Text("No images in the current directory.")
            else -> {
                GalleryGrid(
                    items = state.galleryItems,
                    onItemClick = { index -> fullscreenIndex = index },
                )
                Text(
                    text = "Pinch the gallery to change thumbnail density.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }

    val selectedIndex = fullscreenIndex
    if (selectedIndex != null && state.galleryItems.isNotEmpty()) {
        GalleryFullscreenViewer(
            items = state.galleryItems,
            initialIndex = selectedIndex.coerceIn(0, state.galleryItems.lastIndex),
            onDismiss = { fullscreenIndex = null },
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun GalleryGrid(
    items: List<GalleryImageItem>,
    onItemClick: (Int) -> Unit,
) {
    BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
        val density = LocalDensity.current
        val gap = 12.dp
        val autoColumns = when {
            maxWidth < 420.dp -> 2
            maxWidth < 800.dp -> 3
            else -> 4
        }
        var columns by rememberSaveable(autoColumns) { mutableIntStateOf(autoColumns) }
        val maxColumns = 6
        var accumulatedZoom by remember { mutableFloatStateOf(1f) }
        val clampedColumns = columns.coerceIn(1, maxColumns)
        if (clampedColumns != columns) {
            columns = clampedColumns
        }
        val cardWidth = with(density) {
            val availableWidthPx =
                (maxWidth.roundToPx() - gap.roundToPx() * (columns - 1)).coerceAtLeast(columns)
            (availableWidthPx / columns).toDp()
        }

        FlowRow(
            modifier = Modifier
                .fillMaxWidth()
                .galleryGridPinchGesture(
                    onPinch = { zoom ->
                        accumulatedZoom *= zoom
                        if (accumulatedZoom > 1.12f) {
                            columns = (columns - 1).coerceAtLeast(1)
                            accumulatedZoom = 1f
                        } else if (accumulatedZoom < 0.88f) {
                            columns = (columns + 1).coerceAtMost(maxColumns)
                            accumulatedZoom = 1f
                        }
                    },
                ),
            maxItemsInEachRow = columns,
            horizontalArrangement = Arrangement.spacedBy(gap),
            verticalArrangement = Arrangement.spacedBy(gap),
        ) {
            items.forEachIndexed { index, item ->
                GalleryCard(
                    item = item,
                    showDetails = columns < 3,
                    onClick = { onItemClick(index) },
                    modifier = Modifier.width(cardWidth),
                )
            }
        }
    }
}

@Composable
private fun GalleryCard(
    item: GalleryImageItem,
    showDetails: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.clickable(onClick = onClick),
        tonalElevation = 2.dp,
        shape = RoundedCornerShape(20.dp),
    ) {
        Column {
            ProviderThumbnail(
                documentUri = item.documentUri,
                contentDescription = item.displayName,
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(1f),
            )

            if (showDetails) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text = item.displayName,
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = item.remotePath,
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    galleryMetaText(item)?.let { meta ->
                        Text(
                            text = meta,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    item.createdAtUnixMs?.let { createdAt ->
                        Text(
                            text = "Created ${formatTimestamp(createdAt)}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class)
@Composable
private fun GalleryFullscreenViewer(
    items: List<GalleryImageItem>,
    initialIndex: Int,
    onDismiss: () -> Unit,
) {
    val zoomedPages = remember { mutableStateMapOf<Int, Boolean>() }
    val pagerState = rememberPagerState(
        initialPage = initialIndex,
        pageCount = { items.size },
    )
    BackHandler(onBack = onDismiss)

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = false,
        ),
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = Color.Black,
        ) {
            Box(modifier = Modifier.fillMaxSize()) {
                HorizontalPager(
                    state = pagerState,
                    userScrollEnabled = zoomedPages[pagerState.currentPage] != true,
                    modifier = Modifier.fillMaxSize(),
                ) { page ->
                    GalleryFullscreenPage(
                        item = items[page],
                        onZoomStateChanged = { zoomed ->
                            zoomedPages[page] = zoomed
                        },
                    )
                }

                Surface(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .fillMaxWidth()
                        .statusBarsPadding(),
                    color = Color.Black.copy(alpha = 0.55f),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        OutlinedButton(onClick = onDismiss) {
                            Text("Close")
                        }
                        Text(
                            text = items[pagerState.currentPage].displayName,
                            color = Color.White,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            text = "${pagerState.currentPage + 1}/${items.size}",
                            color = Color.White,
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }

                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth()
                        .navigationBarsPadding(),
                    color = Color.Black.copy(alpha = 0.55f),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        val item = items[pagerState.currentPage]
                        Text(
                            text = item.remotePath,
                            color = Color.White,
                            style = MaterialTheme.typography.bodyMedium,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        galleryMetaText(item)?.let { meta ->
                            Text(
                                text = meta,
                                color = Color.White.copy(alpha = 0.8f),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        item.createdAtUnixMs?.let { createdAt ->
                            Text(
                                text = "Created ${formatTimestamp(createdAt)}",
                                color = Color.White.copy(alpha = 0.8f),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
            }
        }
    }
}

private sealed interface GalleryFullscreenImageState {
    data object Loading : GalleryFullscreenImageState

    data class Loaded(val bitmap: Bitmap) : GalleryFullscreenImageState

    data object Failed : GalleryFullscreenImageState
}

@Composable
private fun GalleryFullscreenPage(
    item: GalleryImageItem,
    onZoomStateChanged: (Boolean) -> Unit,
) {
    val context = LocalContext.current
    val density = LocalDensity.current
    var scale by remember(item.documentUri) { mutableFloatStateOf(1f) }
    var offsetX by remember(item.documentUri) { mutableFloatStateOf(0f) }
    var offsetY by remember(item.documentUri) { mutableFloatStateOf(0f) }
    val imageState by produceState<GalleryFullscreenImageState>(
        initialValue = GalleryFullscreenImageState.Loading,
        key1 = item.documentUri,
    ) {
        value = withContext(Dispatchers.IO) {
            DocumentBitmapLoader.load(
                context = context,
                contentResolver = context.contentResolver,
                documentUri = item.documentUri,
                maxDimensionPx = 2048,
            )?.let { bitmap ->
                GalleryFullscreenImageState.Loaded(bitmap)
            } ?: GalleryFullscreenImageState.Failed
        }
    }

    LaunchedEffect(scale) {
        onZoomStateChanged(scale > 1.01f)
    }

    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .clipToBounds(),
        contentAlignment = Alignment.Center,
    ) {
        val widthPx = with(density) { maxWidth.toPx() }
        val heightPx = with(density) { maxHeight.toPx() }
        when (val state = imageState) {
            is GalleryFullscreenImageState.Loaded -> {
                val loadedBitmap = state.bitmap
                val fittedSize = fittedImageSize(
                    imageWidth = loadedBitmap.width.toFloat(),
                    imageHeight = loadedBitmap.height.toFloat(),
                    containerWidth = widthPx,
                    containerHeight = heightPx,
                )
                Image(
                    bitmap = loadedBitmap.asImageBitmap(),
                    contentDescription = item.displayName,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier
                        .fillMaxSize()
                        .zoomableImageGesture(
                            gestureKey = item.documentUri,
                            fittedSize = fittedSize,
                            containerWidth = widthPx,
                            containerHeight = heightPx,
                            scale = { scale },
                            offset = { Offset(offsetX, offsetY) },
                            onTransform = { newScale, newOffset ->
                                scale = newScale
                                offsetX = newOffset.x
                                offsetY = newOffset.y
                            },
                        )
                        .graphicsLayer {
                            scaleX = scale
                            scaleY = scale
                            translationX = offsetX
                            translationY = offsetY
                        },
                )
            }

            GalleryFullscreenImageState.Loading -> {
                CircularProgressIndicator(color = Color.White)
            }

            GalleryFullscreenImageState.Failed -> {
                Text(
                    text = "Image unavailable",
                    color = Color.White,
                    style = MaterialTheme.typography.titleMedium,
                )
            }
        }
    }
}

@Composable
private fun ProviderThumbnail(
    documentUri: Uri,
    contentDescription: String,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val thumbnail by produceState<Bitmap?>(initialValue = null, documentUri) {
        value = withContext(Dispatchers.IO) {
            loadDocumentThumbnail(context.contentResolver, documentUri, 384)
        }
    }

    Box(
        modifier = modifier.background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        val bitmap = thumbnail
        if (bitmap != null) {
            Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = contentDescription,
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Text(
                text = "Preview unavailable",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(12.dp),
            )
        }
    }
}

private fun galleryMetaText(item: GalleryImageItem): String? {
    val parts = mutableListOf<String>()
    if (item.width != null && item.height != null) {
        parts += "${item.width} x ${item.height}"
    }
    if (!item.thumbnailStatus.isNullOrBlank()) {
        parts += item.thumbnailStatus
    }
    return parts.takeIf { it.isNotEmpty() }?.joinToString(" | ")
}

private fun loadDocumentThumbnail(
    contentResolver: ContentResolver,
    documentUri: Uri,
    sizePx: Int,
): Bitmap? {
    return runCatching {
        DocumentsContract.getDocumentThumbnail(
            contentResolver,
            documentUri,
            Point(sizePx, sizePx),
            null,
        )
    }.onFailure { error ->
        Log.w("LibraryScreen", "Thumbnail load failed for $documentUri: ${error.message}")
    }.getOrNull()
}

private fun Modifier.galleryGridPinchGesture(
    onPinch: (Float) -> Unit,
): Modifier = pointerInput(Unit) {
    awaitEachGesture {
        awaitFirstDown(requireUnconsumed = false)
        do {
            val event = awaitPointerEvent()
            val pointerCount = event.changes.count { it.pressed }
            if (pointerCount >= 2) {
                val zoom = event.calculateZoom()
                if (abs(zoom - 1f) > 0.01f) {
                    onPinch(zoom)
                    event.changes.forEach { change ->
                        if (change.pressed) {
                            change.consume()
                        }
                    }
                }
            }
        } while (event.changes.any { it.pressed })
    }
}

private fun Modifier.zoomableImageGesture(
    gestureKey: Any?,
    fittedSize: FittedImageSize,
    containerWidth: Float,
    containerHeight: Float,
    scale: () -> Float,
    offset: () -> Offset,
    onTransform: (Float, Offset) -> Unit,
): Modifier = pointerInput(gestureKey, fittedSize, containerWidth, containerHeight) {
    awaitEachGesture {
        awaitFirstDown(requireUnconsumed = false)
        do {
            val event = awaitPointerEvent()
            val pressedChanges = event.changes.filter { it.pressed }
            if (pressedChanges.isEmpty()) {
                break
            }

            val currentScale = scale()
            val currentOffset = offset()
            val zoomChange = if (pressedChanges.size >= 2) event.calculateZoom() else 1f
            val panChange = when {
                pressedChanges.size >= 2 -> event.calculatePan()
                currentScale > 1.01f -> pressedChanges.first().positionChange()
                else -> Offset.Zero
            }
            val nextScale = (currentScale * zoomChange).coerceIn(1f, 5f)
            val shouldHandleZoom = pressedChanges.size >= 2 && abs(zoomChange - 1f) > 0.01f
            val shouldHandlePan =
                panChange != Offset.Zero && (currentScale > 1.01f || nextScale > 1.01f)
            if (!shouldHandleZoom && !shouldHandlePan) {
                continue
            }

            onTransform(
                nextScale,
                boundedImageOffset(
                    scale = currentScale,
                    nextScale = nextScale,
                    offset = currentOffset,
                    pan = panChange,
                    fittedSize = fittedSize,
                    containerWidth = containerWidth,
                    containerHeight = containerHeight,
                ),
            )
            event.changes.forEach { change ->
                if (change.pressed) {
                    change.consume()
                }
            }
        } while (event.changes.any { it.pressed })
    }
}

private data class FittedImageSize(
    val width: Float,
    val height: Float,
)

private fun boundedImageOffset(
    scale: Float,
    nextScale: Float,
    offset: Offset,
    pan: Offset,
    fittedSize: FittedImageSize,
    containerWidth: Float,
    containerHeight: Float,
): Offset {
    if (nextScale <= 1.01f) {
        return Offset.Zero
    }

    val scaleChange = if (scale == 0f) 1f else nextScale / scale
    val rawOffset = Offset(
        x = (offset.x + pan.x) * scaleChange,
        y = (offset.y + pan.y) * scaleChange,
    )
    val maxOffsetX = ((fittedSize.width * nextScale) - containerWidth).coerceAtLeast(0f) / 2f
    val maxOffsetY = ((fittedSize.height * nextScale) - containerHeight).coerceAtLeast(0f) / 2f
    return Offset(
        x = rawOffset.x.coerceIn(-maxOffsetX, maxOffsetX),
        y = rawOffset.y.coerceIn(-maxOffsetY, maxOffsetY),
    )
}

private fun fittedImageSize(
    imageWidth: Float,
    imageHeight: Float,
    containerWidth: Float,
    containerHeight: Float,
): FittedImageSize {
    if (
        imageWidth <= 0f ||
        imageHeight <= 0f ||
        containerWidth <= 0f ||
        containerHeight <= 0f
    ) {
        return FittedImageSize(containerWidth, containerHeight)
    }

    val scale = minOf(containerWidth / imageWidth, containerHeight / imageHeight)
    return FittedImageSize(
        width = imageWidth * scale,
        height = imageHeight * scale,
    )
}
