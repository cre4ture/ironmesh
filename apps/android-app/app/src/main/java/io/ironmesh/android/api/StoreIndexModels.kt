package io.ironmesh.android.api

data class StoreIndexResponse(
    val prefix: String,
    val depth: Int,
    val entry_count: Int,
    val total_entry_count: Int = entry_count,
    val offset: Int = 0,
    val limit: Int? = null,
    val has_more: Boolean = false,
    val entries: List<StoreIndexEntry>,
)

enum class StoreIndexView(
    val wireValue: String,
) {
    RAW("raw"),
    TREE("tree"),
}

enum class StoreIndexSortOrder(
    val wireValue: String,
) {
    PATH_ASC("path_asc"),
    CAPTURED_DESC("captured_desc"),
}

enum class StoreIndexMediaFilter(
    val wireValue: String,
) {
    ALL("all"),
    IMAGE("image"),
    VIDEO("video"),
}

data class StoreIndexRequestOptions(
    val view: StoreIndexView? = null,
    val offset: Int? = null,
    val limit: Int? = null,
    val sort: StoreIndexSortOrder? = null,
    val mediaFilter: StoreIndexMediaFilter? = null,
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
