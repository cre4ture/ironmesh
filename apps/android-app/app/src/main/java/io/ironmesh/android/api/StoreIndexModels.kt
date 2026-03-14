package io.ironmesh.android.api

data class StoreIndexResponse(
    val prefix: String,
    val depth: Int,
    val entry_count: Int,
    val entries: List<StoreIndexEntry>,
)

data class StoreIndexEntry(
    val path: String,
    val entry_type: String,
    val content_hash: String? = null,
    val content_fingerprint: String? = null,
    val media: StoreIndexMedia? = null,
)

data class StoreIndexMedia(
    val status: String,
    val content_fingerprint: String,
    val media_type: String? = null,
    val mime_type: String? = null,
    val width: Int? = null,
    val height: Int? = null,
    val orientation: Int? = null,
    val taken_at_unix: Long? = null,
    val gps: StoreIndexGps? = null,
    val thumbnail: StoreIndexThumbnail? = null,
    val error: String? = null,
)

data class StoreIndexGps(
    val latitude: Double,
    val longitude: Double,
)

data class StoreIndexThumbnail(
    val url: String,
    val profile: String,
    val width: Int,
    val height: Int,
    val format: String,
    val size_bytes: Long,
)
