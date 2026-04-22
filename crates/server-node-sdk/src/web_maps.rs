use super::*;
use axum::http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_RANGE, CONTENT_TYPE, ETAG, RANGE,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

mod mbtiles;

pub(crate) use mbtiles::LogicalMbtilesSource;

const MAX_FULL_LOGICAL_FILE_GET_BYTES: u64 = 64 * 1024 * 1024;
const MAP_MANIFEST_PREFIX: &str = "sys/maps/";

#[derive(Debug, Deserialize)]
pub(crate) struct WebMapLogicalFileQuery {
    manifest_key: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct WebMapMbtilesMetadataResponse {
    attribution: Option<String>,
    center: Option<[f64; 3]>,
    format: Option<String>,
    id: Option<String>,
    minzoom: Option<u8>,
    maxzoom: Option<u8>,
    name: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ErrorResponseBody {
    error: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SplitLogicalFileManifest {
    manifest_version: u32,
    #[serde(rename = "type")]
    manifest_type: String,
    logical_format: String,
    logical_key: String,
    logical_size_bytes: u64,
    parts_count: usize,
    parts: Vec<SplitLogicalFilePart>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SplitLogicalFilePart {
    part_id: String,
    key: String,
    offset_bytes: u64,
    size_bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct LoadedSplitLogicalFileManifest {
    pub(crate) manifest: SplitLogicalFileManifest,
    pub(crate) resolved_parts: Vec<LoadedSplitLogicalFilePart>,
    pub(crate) etag: String,
}

#[derive(Clone, Debug)]
pub(crate) struct LoadedSplitLogicalFilePart {
    pub(crate) manifest_hash: String,
}

#[derive(Clone, Copy, Debug)]
struct LogicalFileByteRange {
    start: u64,
    end_inclusive: u64,
}

pub(crate) async fn mbtiles_metadata(
    State(state): State<ServerState>,
    Query(query): Query<WebMapLogicalFileQuery>,
) -> impl IntoResponse {
    let manifest_key = match validate_manifest_key(&query.manifest_key) {
        Ok(key) => key,
        Err((status, message)) => return error_response(status, message),
    };
    let started = Instant::now();

    let source = match get_or_create_mbtiles_source(&state, &manifest_key).await {
        Ok(source) => source,
        Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    };
    let metadata = source.metadata();

    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %manifest_key,
            minzoom = metadata.minzoom.unwrap_or_default(),
            maxzoom = metadata.maxzoom.unwrap_or_default(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: served MBTiles metadata"
        );
    }

    (
        StatusCode::OK,
        Json(WebMapMbtilesMetadataResponse {
            attribution: metadata.attribution.clone(),
            center: metadata.center,
            format: metadata.format.clone(),
            id: metadata.id.clone(),
            minzoom: metadata.minzoom,
            maxzoom: metadata.maxzoom,
            name: metadata.name.clone(),
            version: metadata.version.clone(),
        }),
    )
        .into_response()
}

pub(crate) async fn logical_file(
    State(state): State<ServerState>,
    method: axum::http::Method,
    headers: HeaderMap,
    Query(query): Query<WebMapLogicalFileQuery>,
) -> impl IntoResponse {
    let manifest_key = match validate_manifest_key(&query.manifest_key) {
        Ok(key) => key,
        Err((status, message)) => return error_response(status, message),
    };
    let started = Instant::now();

    let loaded_manifest = match load_split_logical_file_manifest(&state, &manifest_key).await {
        Ok(manifest) => manifest,
        Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    };

    let total_size_bytes = loaded_manifest.manifest.logical_size_bytes;
    let selected_range = match headers
        .get(RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|value| parse_logical_file_range(value, total_size_bytes))
    {
        Some(Some(range)) => Some(range),
        Some(None) => {
            let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            let response_headers = response.headers_mut();
            response_headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            response_headers.insert(
                CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{total_size_bytes}"))
                    .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
            );
            response_headers.insert(
                ETAG,
                HeaderValue::from_str(&loaded_manifest.etag)
                    .unwrap_or_else(|_| HeaderValue::from_static("\"invalid-etag\"")),
            );
            return response;
        }
        None => None,
    };

    if method != axum::http::Method::HEAD
        && selected_range.is_none()
        && total_size_bytes > MAX_FULL_LOGICAL_FILE_GET_BYTES
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "full logical file GET is disabled for files larger than {MAX_FULL_LOGICAL_FILE_GET_BYTES} bytes; use range requests"
            ),
        );
    }

    let content_length = selected_range
        .map(|range| {
            range
                .end_inclusive
                .saturating_sub(range.start)
                .saturating_add(1)
        })
        .unwrap_or(total_size_bytes);

    let mut response_headers = HeaderMap::new();
    response_headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response_headers.insert(
        ETAG,
        HeaderValue::from_str(&loaded_manifest.etag)
            .unwrap_or_else(|_| HeaderValue::from_static("\"invalid-etag\"")),
    );
    response_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(logical_file_content_type(
            &loaded_manifest.manifest.logical_format,
        )),
    );
    response_headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "inline; filename=\"{}\"",
            file_name_from_key(&loaded_manifest.manifest.logical_key)
        ))
        .unwrap_or_else(|_| HeaderValue::from_static("inline")),
    );
    response_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    if let Some(range) = selected_range {
        response_headers.insert(
            CONTENT_RANGE,
            HeaderValue::from_str(&format!(
                "bytes {}-{}/{}",
                range.start, range.end_inclusive, total_size_bytes
            ))
            .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
        );
    }

    if method == axum::http::Method::HEAD {
        return (
            selected_range
                .map(|_| StatusCode::PARTIAL_CONTENT)
                .unwrap_or(StatusCode::OK),
            response_headers,
            Vec::<u8>::new(),
        )
            .into_response();
    }

    let range_start = selected_range.map(|range| range.start).unwrap_or(0);
    let range_length = selected_range
        .map(|range| {
            range
                .end_inclusive
                .saturating_sub(range.start)
                .saturating_add(1)
        })
        .unwrap_or(total_size_bytes);
    let body = match read_logical_range_bytes_from_store(
        &state.store,
        &loaded_manifest,
        range_start,
        range_length,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    };

    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %manifest_key,
            method = %method,
            range_start,
            range_length,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: served logical file bytes"
        );
    }

    (
        selected_range
            .map(|_| StatusCode::PARTIAL_CONTENT)
            .unwrap_or(StatusCode::OK),
        response_headers,
        body,
    )
        .into_response()
}

pub(crate) async fn xyz_tile(
    State(state): State<ServerState>,
    Path((z, x, y)): Path<(u32, u32, u32)>,
    Query(query): Query<WebMapLogicalFileQuery>,
) -> impl IntoResponse {
    let manifest_key = match validate_manifest_key(&query.manifest_key) {
        Ok(key) => key,
        Err((status, message)) => return error_response(status, message),
    };
    let started = Instant::now();

    let source = match get_or_create_mbtiles_source(&state, &manifest_key).await {
        Ok(source) => source,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    let tile_lookup = tokio::task::spawn_blocking({
        let cancelled = Arc::new(AtomicBool::new(false));
        move || source.lookup_tile_with_cancellation(z, x, y, cancelled)
    })
    .await;
    let tile = match tile_lookup {
        Ok(Ok(Some(tile))) => tile,
        Ok(Ok(None)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(_)) | Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %manifest_key,
            z,
            x,
            y,
            bytes = tile.bytes.len(),
            content_type = tile.content_type,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: served raster XYZ tile"
        );
    }

    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, HeaderValue::from_static(tile.content_type));
    response_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, stale-while-revalidate=86400"),
    );

    (StatusCode::OK, response_headers, tile.bytes).into_response()
}

pub(crate) async fn vector_tile(
    State(state): State<ServerState>,
    Path((z, x, y)): Path<(u32, u32, u32)>,
    Query(query): Query<WebMapLogicalFileQuery>,
) -> impl IntoResponse {
    let manifest_key = match validate_manifest_key(&query.manifest_key) {
        Ok(key) => key,
        Err((status, message)) => return error_response(status, message),
    };
    let started = Instant::now();

    let source = match get_or_create_mbtiles_source(&state, &manifest_key).await {
        Ok(source) => source,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    let tile_lookup = tokio::task::spawn_blocking({
        let cancelled = Arc::new(AtomicBool::new(false));
        move || source.lookup_vector_tile_with_cancellation(z, x, y, cancelled)
    })
    .await;
    let tile = match tile_lookup {
        Ok(Ok(Some(tile))) => tile,
        Ok(Ok(None)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(_)) | Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %manifest_key,
            z,
            x,
            y,
            bytes = tile.bytes.len(),
            content_encoding = tile.content_encoding.unwrap_or("identity"),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: served vector XYZ tile"
        );
    }

    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, HeaderValue::from_static(tile.content_type));
    if let Some(content_encoding) = tile.content_encoding {
        response_headers.insert(CONTENT_ENCODING, HeaderValue::from_static(content_encoding));
    }
    response_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, stale-while-revalidate=86400"),
    );

    (StatusCode::OK, response_headers, tile.bytes).into_response()
}

pub(crate) async fn font_range(
    State(state): State<ServerState>,
    Path((fontstack, range)): Path<(String, String)>,
) -> impl IntoResponse {
    let Some(glyphs_root) = state.map_glyphs_root.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    if !is_safe_fontstack_segment(&fontstack) || !is_safe_glyph_range_segment(&range) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let path = glyphs_root.join(&fontstack).join(&range);
    if !path.starts_with(&glyphs_root) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let mut response_headers = HeaderMap::new();
            response_headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-protobuf"),
            );
            response_headers.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400, stale-while-revalidate=604800"),
            );
            (StatusCode::OK, response_headers, bytes).into_response()
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

pub(crate) fn resolve_map_glyphs_root(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = explicit.filter(|path| path.is_dir()) {
        return Some(path);
    }

    if let Ok(value) = std::env::var("IRONMESH_MAP_GLYPHS_DIR") {
        let path = PathBuf::from(value);
        if path.is_dir() {
            return Some(path);
        }
    }

    let repo_relative = PathBuf::from("map/maptiler-server-map-styles-and-samples-3.15/fonts");
    if repo_relative.is_dir() {
        return Some(repo_relative);
    }

    None
}

pub(crate) async fn read_logical_range_bytes_from_store(
    store: &Arc<TracedRwLock<PersistentStore>>,
    loaded_manifest: &LoadedSplitLogicalFileManifest,
    start: u64,
    length: u64,
) -> Result<Vec<u8>> {
    let end_exclusive = start
        .checked_add(length)
        .ok_or_else(|| anyhow!("logical MBTiles range overflow"))?;
    let mut body = Vec::with_capacity(length.min(1024 * 1024) as usize);
    let store = store.read("maps.logical_range.read").await;

    for (part, resolved_part) in loaded_manifest
        .manifest
        .parts
        .iter()
        .zip(loaded_manifest.resolved_parts.iter())
    {
        let part_start = part.offset_bytes;
        let part_end_exclusive = part
            .offset_bytes
            .checked_add(part.size_bytes)
            .ok_or_else(|| anyhow!("manifest part end overflow for {}", part.part_id))?;
        if part_end_exclusive <= start || part_start >= end_exclusive {
            continue;
        }

        let segment_start = start.max(part_start);
        let segment_end_exclusive = end_exclusive.min(part_end_exclusive);
        let local_start = segment_start.saturating_sub(part_start);
        let segment_length = segment_end_exclusive.saturating_sub(segment_start);
        if segment_length == 0 {
            continue;
        }

        let local_start = usize::try_from(local_start)
            .context("logical MBTiles local range start does not fit in usize")?;
        let segment_length = usize::try_from(segment_length)
            .context("logical MBTiles segment length does not fit in usize")?;
        let local_end_exclusive = local_start
            .checked_add(segment_length)
            .ok_or_else(|| anyhow!("logical MBTiles local range overflow"))?;
        let bytes = store
            .read_object_range_by_manifest_hash(
                &resolved_part.manifest_hash,
                local_start,
                local_end_exclusive,
            )
            .await
            .map_err(store_read_error_to_anyhow)?;
        body.extend_from_slice(bytes.as_ref());
    }

    if body.len() as u64 != length {
        return Err(anyhow!(
            "logical MBTiles segment reconstruction produced {} bytes, expected {}",
            body.len(),
            length
        ));
    }

    Ok(body)
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponseBody {
            error: message.into(),
        }),
    )
        .into_response()
}

fn validate_manifest_key(raw: &str) -> std::result::Result<String, (StatusCode, String)> {
    let manifest_key = raw.trim();
    if manifest_key.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest_key must not be empty".to_string(),
        ));
    }
    if !manifest_key.starts_with(MAP_MANIFEST_PREFIX) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("manifest_key must be under {MAP_MANIFEST_PREFIX}"),
        ));
    }
    Ok(manifest_key.to_string())
}

fn parse_logical_file_range(value: &str, total_size_bytes: u64) -> Option<LogicalFileByteRange> {
    if total_size_bytes == 0 {
        return None;
    }

    let trimmed = value.trim();
    let range_spec = trimmed.strip_prefix("bytes=")?.trim();
    if range_spec.contains(',') {
        return None;
    }

    let (start_raw, end_raw) = range_spec.split_once('-')?;
    if start_raw.is_empty() {
        let suffix_length = end_raw.parse::<u64>().ok()?;
        if suffix_length == 0 {
            return None;
        }

        let start = total_size_bytes.saturating_sub(suffix_length);
        return Some(LogicalFileByteRange {
            start,
            end_inclusive: total_size_bytes.saturating_sub(1),
        });
    }

    let start = start_raw.parse::<u64>().ok()?;
    if start >= total_size_bytes {
        return None;
    }

    let end_inclusive = if end_raw.is_empty() {
        total_size_bytes.saturating_sub(1)
    } else {
        let end = end_raw.parse::<u64>().ok()?;
        if end < start {
            return None;
        }
        end.min(total_size_bytes.saturating_sub(1))
    };

    Some(LogicalFileByteRange {
        start,
        end_inclusive,
    })
}

fn logical_file_content_type(logical_format: &str) -> &'static str {
    if logical_format.eq_ignore_ascii_case("mbtiles") {
        "application/vnd.sqlite3"
    } else {
        "application/octet-stream"
    }
}

fn file_name_from_key(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

fn validate_split_logical_file_manifest(
    mut manifest: SplitLogicalFileManifest,
) -> Result<SplitLogicalFileManifest> {
    if manifest.manifest_version != 1 {
        bail!(
            "unsupported split logical file manifest version: {}",
            manifest.manifest_version
        );
    }
    if manifest.manifest_type != "split_file_manifest" {
        bail!(
            "unsupported split logical file manifest type: {}",
            manifest.manifest_type
        );
    }
    if manifest.logical_key.trim().is_empty() {
        bail!("logical_key must not be empty");
    }
    if manifest.parts_count != manifest.parts.len() {
        bail!(
            "parts_count mismatch: declared={} actual={}",
            manifest.parts_count,
            manifest.parts.len()
        );
    }
    if manifest.parts.is_empty() {
        bail!("split logical file manifest must contain at least one part");
    }

    manifest.parts.sort_by_key(|part| part.offset_bytes);
    let mut expected_offset = 0_u64;
    for part in &manifest.parts {
        if part.part_id.trim().is_empty() {
            bail!("manifest part_id must not be empty");
        }
        if part.key.trim().is_empty() {
            bail!("manifest part key must not be empty");
        }
        if part.size_bytes == 0 {
            bail!("manifest part {} has zero size", part.part_id);
        }
        if part.offset_bytes != expected_offset {
            bail!(
                "manifest part {} offset mismatch: expected={} actual={}",
                part.part_id,
                expected_offset,
                part.offset_bytes
            );
        }
        expected_offset = expected_offset
            .checked_add(part.size_bytes)
            .ok_or_else(|| anyhow!("manifest logical size overflow"))?;
    }

    if expected_offset != manifest.logical_size_bytes {
        bail!(
            "manifest logical_size_bytes mismatch: declared={} actual={}",
            manifest.logical_size_bytes,
            expected_offset
        );
    }

    Ok(manifest)
}

async fn load_split_logical_file_manifest(
    state: &ServerState,
    manifest_key: &str,
) -> Result<LoadedSplitLogicalFileManifest> {
    let started = Instant::now();
    let manifest_descriptor = {
        let store = read_store(state, "maps.manifest.describe").await;
        store
            .describe_object(manifest_key, None, None, ObjectReadMode::Preferred)
            .await
            .map_err(store_read_error_to_anyhow)?
    };

    let manifest_payload = {
        let store = read_store(state, "maps.manifest.read").await;
        store
            .read_object_range_by_manifest_hash(
                &manifest_descriptor.manifest_hash,
                0,
                manifest_descriptor.total_size_bytes,
            )
            .await
            .map_err(store_read_error_to_anyhow)?
    };

    let manifest = serde_json::from_slice::<SplitLogicalFileManifest>(manifest_payload.as_ref())
        .with_context(|| format!("failed to parse split logical file manifest {manifest_key}"))?;
    let manifest = validate_split_logical_file_manifest(manifest)?;

    let mut resolved_parts = Vec::with_capacity(manifest.parts.len());
    {
        let store = read_store(state, "maps.manifest.resolve_parts").await;
        for part in &manifest.parts {
            let descriptor = store
                .describe_object(&part.key, None, None, ObjectReadMode::Preferred)
                .await
                .map_err(store_read_error_to_anyhow)
                .with_context(|| {
                    format!("failed to resolve split logical file part {}", part.key)
                })?;
            if descriptor.total_size_bytes as u64 != part.size_bytes {
                bail!(
                    "split logical file part size mismatch for {}: declared={} actual={}",
                    part.key,
                    part.size_bytes,
                    descriptor.total_size_bytes
                );
            }
            resolved_parts.push(LoadedSplitLogicalFilePart {
                manifest_hash: descriptor.manifest_hash,
            });
        }
    }

    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %manifest_key,
            parts = manifest.parts.len(),
            logical_size_bytes = manifest.logical_size_bytes,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: loaded split logical file manifest"
        );
    }

    Ok(LoadedSplitLogicalFileManifest {
        manifest,
        resolved_parts,
        etag: object_etag(&manifest_descriptor.manifest_hash),
    })
}

async fn get_or_create_mbtiles_source(
    state: &ServerState,
    manifest_key: &str,
) -> Result<Arc<LogicalMbtilesSource>> {
    let started = Instant::now();
    if let Some(source) = state
        .mbtiles_sources
        .read()
        .await
        .get(manifest_key)
        .cloned()
    {
        if state.map_perf_logging_enabled {
            info!(
                manifest_key = %manifest_key,
                cache = "hit",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "map perf: reusing cached MBTiles source"
            );
        }
        return Ok(source);
    }

    let loaded_manifest = load_split_logical_file_manifest(state, manifest_key).await?;
    let handle = tokio::runtime::Handle::current();
    let manifest_key_owned = manifest_key.to_string();
    let perf_logging_enabled = state.map_perf_logging_enabled;
    let source = tokio::task::spawn_blocking({
        let store = state.store.clone();
        move || {
            mbtiles::LogicalMbtilesSource::new(
                manifest_key_owned,
                store,
                handle,
                loaded_manifest,
                perf_logging_enabled,
            )
        }
    })
    .await
    .context("MBTiles source construction task join failed")??;
    let source = Arc::new(source);

    let mut sources = state.mbtiles_sources.write().await;
    if let Some(existing) = sources.get(manifest_key) {
        if state.map_perf_logging_enabled {
            info!(
                manifest_key = %manifest_key,
                cache = "race-hit",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "map perf: reusing concurrently initialized MBTiles source"
            );
        }
        return Ok(existing.clone());
    }
    sources.insert(manifest_key.to_string(), source.clone());
    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %manifest_key,
            cache = "miss",
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: initialized MBTiles source"
        );
    }
    Ok(source)
}

fn is_safe_fontstack_segment(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && !value.split('.').any(|segment| segment == "..")
}

fn is_safe_glyph_range_segment(value: &str) -> bool {
    if value.contains('/') || value.contains('\\') || value.contains('\0') {
        return false;
    }
    let Some((start, end)) = value.split_once('-') else {
        return false;
    };
    let Some(end) = end.strip_suffix(".pbf") else {
        return false;
    };
    !start.is_empty()
        && !end.is_empty()
        && start.chars().all(|ch| ch.is_ascii_digit())
        && end.chars().all(|ch| ch.is_ascii_digit())
}

fn store_read_error_to_anyhow(error: StoreReadError) -> anyhow::Error {
    match error {
        StoreReadError::NotFound => anyhow!("object not found"),
        StoreReadError::Corrupt(message) => anyhow!(message),
        StoreReadError::Internal(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorResponseBody, error_response};
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn error_response_preserves_public_json_contract() {
        let response = error_response(StatusCode::BAD_REQUEST, "bad manifest");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("error response body should be readable");
        let payload: ErrorResponseBody =
            serde_json::from_slice(&body).expect("error response should be valid json");

        assert_eq!(
            payload,
            ErrorResponseBody {
                error: "bad manifest".to_string(),
            }
        );
    }
}
