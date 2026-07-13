use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::extract::State;
use exif::{In, Reader as ExifReader, Tag, Value};
use image::codecs::jpeg::JpegEncoder;
use image::metadata::Orientation;
use image::{DynamicImage, ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use time::{Date, Month, PrimitiveDateTime, Time, UtcOffset};
use tokio::fs;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task;
use tokio::time::{Duration, Instant, timeout};
use tracing::{info, warn};
use uuid::Uuid;

use super::media_tools::{
    FFMPEG_TIMEOUT_SECS, FFPROBE_TIMEOUT_SECS, FfprobeOutput, MediaToolPaths,
    VIDEO_THUMBNAIL_SEEK_FRACTION, VIDEO_THUMBNAIL_SEEK_MAX_SECS, VIDEO_THUMBNAIL_SEEK_MIN_SECS,
    VIDEO_THUMBNAIL_UNKNOWN_DURATION_SEEK_SECS,
};
use super::{
    MetadataStore, ObjectManifest, TOMBSTONE_MANIFEST_HASH, chunk_path_for_hash,
    content_fingerprint_from_manifest, hash_hex, unix_ts, write_atomic,
};

pub(super) const MEDIA_CACHE_SCHEMA_VERSION: u32 = 5;
pub(super) const MEDIA_CACHE_INCOMPLETE_RETRY_SECS: u64 = 10 * 60;
const MEDIA_CACHE_INCOMPLETE_RETRY_SECS_ENV: &str = "IRONMESH_MEDIA_CACHE_INCOMPLETE_RETRY_SECS";
const MEDIA_CACHE_BUILD_TOTAL_PERMITS_ENV: &str = "IRONMESH_MEDIA_CACHE_BUILD_TOTAL_PERMITS";
const MEDIA_CACHE_BUILD_BYTES_PER_PERMIT_ENV: &str = "IRONMESH_MEDIA_CACHE_BUILD_BYTES_PER_PERMIT";
const MEDIA_CACHE_IMAGE_MAX_DIMENSION_ENV: &str = "IRONMESH_MEDIA_CACHE_IMAGE_MAX_DIMENSION";
const MEDIA_CACHE_IMAGE_MAX_PIXELS_ENV: &str = "IRONMESH_MEDIA_CACHE_IMAGE_MAX_PIXELS";
const MEDIA_CACHE_IMAGE_MAX_DECODE_BYTES_ENV: &str = "IRONMESH_MEDIA_CACHE_IMAGE_MAX_DECODE_BYTES";
const DEFAULT_MEDIA_CACHE_BUILD_TOTAL_PERMITS: u32 = 8;
const DEFAULT_MEDIA_CACHE_BUILD_BYTES_PER_PERMIT: u64 = 16 * 1024 * 1024;
const DEFAULT_MEDIA_CACHE_IMAGE_MAX_DIMENSION: u32 = 12_288;
const DEFAULT_MEDIA_CACHE_IMAGE_MAX_PIXELS: u64 = 40_000_000;
const DEFAULT_MEDIA_CACHE_IMAGE_MAX_DECODE_BYTES: u64 = 256 * 1024 * 1024;
const IMAGE_DECODE_ESTIMATED_BYTES_PER_PIXEL: u64 = 4;
pub(super) const GRID_THUMBNAIL_MAX_DIMENSION: u32 = 256;
pub(super) const GRID_THUMBNAIL_PROFILE: &str = "grid";
pub(super) const MEDIA_FORMAT_SNIFF_BYTES: usize = 64 * 1024;
pub(super) const SLOW_MEDIA_CACHE_GENERATION_LOG_THRESHOLD_MS: u128 = 20000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MediaCacheStatus {
    Ready,
    Incomplete,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaGpsCoordinates {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedThumbnailInfo {
    pub profile: String,
    pub format: String,
    pub width: u32,
    pub height: u32,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMediaMetadata {
    pub schema_version: u32,
    pub content_fingerprint: String,
    pub source_manifest_hash: String,
    pub status: MediaCacheStatus,
    pub media_type: Option<String>,
    pub mime_type: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub orientation: Option<u16>,
    pub taken_at_unix: Option<u64>,
    pub gps: Option<MediaGpsCoordinates>,
    pub thumbnail: Option<CachedThumbnailInfo>,
    pub source_size_bytes: usize,
    pub generated_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_unix: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MediaCacheLookup {
    pub content_fingerprint: String,
    pub metadata: Option<CachedMediaMetadata>,
}

struct RenderedThumbnail {
    payload: Vec<u8>,
    width: u32,
    height: u32,
}

struct DerivedMediaCacheArtifact {
    metadata: CachedMediaMetadata,
    thumbnail_payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(super) struct MediaCacheBuildConfig {
    pub(super) total_permits: u32,
    bytes_per_permit: u64,
    image_limits: MediaCacheImageLimits,
}

#[derive(Debug, Clone)]
pub(super) struct MediaCacheImageLimits {
    pub(super) max_dimension: u32,
    pub(super) max_pixels: u64,
    pub(super) max_decode_bytes: u64,
}

impl Default for MediaCacheImageLimits {
    fn default() -> Self {
        Self {
            max_dimension: positive_env_u32(
                MEDIA_CACHE_IMAGE_MAX_DIMENSION_ENV,
                DEFAULT_MEDIA_CACHE_IMAGE_MAX_DIMENSION,
            ),
            max_pixels: positive_env_u64(
                MEDIA_CACHE_IMAGE_MAX_PIXELS_ENV,
                DEFAULT_MEDIA_CACHE_IMAGE_MAX_PIXELS,
            ),
            max_decode_bytes: positive_env_u64(
                MEDIA_CACHE_IMAGE_MAX_DECODE_BYTES_ENV,
                DEFAULT_MEDIA_CACHE_IMAGE_MAX_DECODE_BYTES,
            ),
        }
    }
}

impl Default for MediaCacheBuildConfig {
    fn default() -> Self {
        Self {
            total_permits: positive_env_u32(
                MEDIA_CACHE_BUILD_TOTAL_PERMITS_ENV,
                DEFAULT_MEDIA_CACHE_BUILD_TOTAL_PERMITS,
            ),
            bytes_per_permit: positive_env_u64(
                MEDIA_CACHE_BUILD_BYTES_PER_PERMIT_ENV,
                DEFAULT_MEDIA_CACHE_BUILD_BYTES_PER_PERMIT,
            ),
            image_limits: MediaCacheImageLimits::default(),
        }
    }
}

impl MediaCacheBuildConfig {
    pub(super) fn permits_for_source_size(&self, source_size_bytes: usize) -> u32 {
        let source_size_bytes = u64::try_from(source_size_bytes).unwrap_or(u64::MAX);
        self.permits_for_estimated_bytes(source_size_bytes)
    }

    fn permits_for_estimated_bytes(&self, estimated_bytes: u64) -> u32 {
        let permits = if estimated_bytes == 0 {
            1
        } else {
            estimated_bytes.div_ceil(self.bytes_per_permit)
        };
        permits.clamp(1, u64::from(self.total_permits)) as u32
    }

    fn image_limits(&self) -> &MediaCacheImageLimits {
        &self.image_limits
    }

    #[cfg(test)]
    pub(super) fn with_image_limits_for_test(
        mut self,
        image_limits: MediaCacheImageLimits,
    ) -> Self {
        self.image_limits = image_limits;
        self
    }
}

impl From<CachedMediaMetadata> for DerivedMediaCacheArtifact {
    fn from(metadata: CachedMediaMetadata) -> Self {
        Self {
            metadata,
            thumbnail_payload: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct MediaCacheWorker {
    pub(super) manifests_dir: PathBuf,
    pub(super) chunks_dir: PathBuf,
    pub(super) media_thumbnails_dir: PathBuf,
    pub(super) media_cache_build_permits: Arc<Semaphore>,
    pub(super) media_cache_build_config: MediaCacheBuildConfig,
    pub(super) metadata_store: Arc<dyn MetadataStore>,
    pub(super) media_tools: MediaToolPaths,
}

impl MediaCacheWorker {
    pub(super) fn new(
        manifests_dir: PathBuf,
        chunks_dir: PathBuf,
        media_thumbnails_dir: PathBuf,
        media_cache_build_permits: Arc<Semaphore>,
        media_cache_build_config: MediaCacheBuildConfig,
        metadata_store: Arc<dyn MetadataStore>,
        media_tools: MediaToolPaths,
    ) -> Self {
        Self {
            manifests_dir,
            chunks_dir,
            media_thumbnails_dir,
            media_cache_build_permits,
            media_cache_build_config,
            metadata_store,
            media_tools,
        }
    }

    pub(crate) async fn ensure_media_metadata(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        self.ensure_media_artifact(manifest_hash, false).await
    }

    pub(crate) async fn ensure_media_cache(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        self.ensure_media_artifact(manifest_hash, true).await
    }

    async fn ensure_media_artifact(
        &self,
        manifest_hash: &str,
        include_thumbnail: bool,
    ) -> Result<Option<CachedMediaMetadata>> {
        let ensure_started_at = Instant::now();
        let now_unix = unix_ts();
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
            return Ok(None);
        };
        let content_fingerprint = content_fingerprint_from_manifest(&manifest);
        let existing = current_media_cache_metadata(
            self.load_cached_media_metadata(&content_fingerprint)
                .await?,
        );
        if let Some(existing) = existing.as_ref() {
            let retry_due = media_cache_retry_due(existing, now_unix);
            let cache_satisfies_request = if retry_due {
                false
            } else {
                !include_thumbnail
                    || existing.thumbnail.is_some()
                    || existing.status != MediaCacheStatus::Ready
            };
            if !cache_satisfies_request {
                // Fall through and rebuild the artifact with a thumbnail.
            } else {
                let total_ms = ensure_started_at.elapsed().as_millis();
                if total_ms >= SLOW_MEDIA_CACHE_GENERATION_LOG_THRESHOLD_MS {
                    warn!(
                        manifest_hash,
                        content_fingerprint = %content_fingerprint,
                        total_ms,
                        cache_hit = true,
                        include_thumbnail,
                        status = ?existing.status,
                        has_thumbnail = existing.thumbnail.is_some(),
                        "slow media cache ensure"
                    );
                }
                return Ok(Some(existing.clone()));
            }
        }

        info!(
            manifest_hash,
            content_fingerprint = %content_fingerprint,
            source_size_bytes = manifest.total_size_bytes,
            include_thumbnail,
            metadata_present = existing.is_some(),
            "media cache build requested"
        );

        let build_started_at = Instant::now();
        let derived = self
            .build_media_cache_artifact(
                &manifest,
                manifest_hash,
                &content_fingerprint,
                include_thumbnail,
            )
            .await;
        let build_record_ms = build_started_at.elapsed().as_millis();
        if include_thumbnail
            && let Some(existing) = existing.as_ref()
            && existing.status == MediaCacheStatus::Ready
            && existing.thumbnail.is_none()
            && (derived.metadata.status != MediaCacheStatus::Ready
                || derived.metadata.thumbnail.is_none())
        {
            let merged = merge_cached_media_metadata_without_thumbnail(existing, &derived.metadata);
            let derived = DerivedMediaCacheArtifact {
                metadata: merged,
                thumbnail_payload: None,
            };
            let persist_started_at = Instant::now();
            self.persist_media_cache_record(&derived).await?;
            let persist_ms = persist_started_at.elapsed().as_millis();
            let total_ms = ensure_started_at.elapsed().as_millis();
            let metadata = &derived.metadata;
            if matches!(
                metadata.status,
                MediaCacheStatus::Failed | MediaCacheStatus::Unsupported
            ) {
                warn!(
                    manifest_hash,
                    content_fingerprint = %content_fingerprint,
                    include_thumbnail,
                    status = ?metadata.status,
                    error = metadata.error.as_deref().unwrap_or(""),
                    "media thumbnail build failed after metadata-only cache"
                );
            }
            info!(
                manifest_hash,
                content_fingerprint = %content_fingerprint,
                total_ms,
                build_record_ms,
                persist_ms,
                include_thumbnail,
                status = ?metadata.status,
                has_thumbnail = metadata.thumbnail.is_some(),
                error = metadata.error.as_deref().unwrap_or(""),
                "media cache build finished"
            );
            if total_ms >= SLOW_MEDIA_CACHE_GENERATION_LOG_THRESHOLD_MS {
                warn!(
                    manifest_hash,
                    content_fingerprint = %content_fingerprint,
                    total_ms,
                    build_record_ms,
                    persist_ms,
                    include_thumbnail,
                    status = ?metadata.status,
                    has_thumbnail = metadata.thumbnail.is_some(),
                    error = metadata.error.as_deref().unwrap_or(""),
                    "slow media cache build"
                );
            }
            return Ok(Some(metadata.clone()));
        }

        let persist_started_at = Instant::now();
        self.persist_media_cache_record(&derived).await?;
        let persist_ms = persist_started_at.elapsed().as_millis();
        let total_ms = ensure_started_at.elapsed().as_millis();
        let metadata = &derived.metadata;
        info!(
            manifest_hash,
            content_fingerprint = %content_fingerprint,
            total_ms,
            build_record_ms,
            persist_ms,
            include_thumbnail,
            status = ?metadata.status,
            has_thumbnail = metadata.thumbnail.is_some(),
            error = metadata.error.as_deref().unwrap_or(""),
            "media cache build finished"
        );
        if total_ms >= SLOW_MEDIA_CACHE_GENERATION_LOG_THRESHOLD_MS {
            warn!(
                manifest_hash,
                content_fingerprint = %content_fingerprint,
                total_ms,
                build_record_ms,
                persist_ms,
                include_thumbnail,
                status = ?metadata.status,
                has_thumbnail = metadata.thumbnail.is_some(),
                error = metadata.error.as_deref().unwrap_or(""),
                "slow media cache build"
            );
        }
        Ok(Some(metadata.clone()))
    }

    pub(crate) async fn import_media_cache_artifact(
        &self,
        mut metadata: CachedMediaMetadata,
        thumbnail_payload: Option<Vec<u8>>,
    ) -> Result<CachedMediaMetadata> {
        if metadata.status != MediaCacheStatus::Ready || thumbnail_payload.is_none() {
            metadata.thumbnail = None;
        }
        metadata.retry_after_unix = None;

        let derived = DerivedMediaCacheArtifact {
            metadata: metadata.clone(),
            thumbnail_payload,
        };
        self.persist_media_cache_record(&derived).await?;
        Ok(metadata)
    }

    async fn load_manifest_by_hash(&self, manifest_hash: &str) -> Result<Option<ObjectManifest>> {
        let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));
        if !fs::try_exists(&manifest_path).await? {
            return Ok(None);
        }

        let payload = fs::read(&manifest_path).await?;
        let manifest = serde_json::from_slice::<ObjectManifest>(&payload)
            .with_context(|| format!("invalid manifest {}", manifest_path.display()))?;
        Ok(Some(manifest))
    }

    async fn load_cached_media_metadata(
        &self,
        content_fingerprint: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        self.metadata_store
            .load_cached_media_metadata(content_fingerprint)
            .await
    }

    async fn build_media_cache_artifact(
        &self,
        manifest: &ObjectManifest,
        manifest_hash: &str,
        content_fingerprint: &str,
        include_thumbnail: bool,
    ) -> DerivedMediaCacheArtifact {
        let generated_at_unix = unix_ts();

        match manifest_chunks_are_locally_complete(manifest, &self.chunks_dir).await {
            Ok(true) => {}
            Ok(false) => {
                return incomplete_media_cache_artifact(
                    manifest_hash,
                    content_fingerprint,
                    manifest.total_size_bytes,
                    generated_at_unix,
                    "media source is incomplete locally; one or more chunks are missing or have the wrong size",
                );
            }
            Err(err) => {
                return failed_media_cache_artifact(
                    manifest_hash,
                    content_fingerprint,
                    manifest.total_size_bytes,
                    generated_at_unix,
                    err.to_string(),
                );
            }
        }

        let sniff_bytes = match read_object_prefix_from_manifest(
            manifest,
            &self.chunks_dir,
            MEDIA_FORMAT_SNIFF_BYTES,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(err) => {
                return failed_media_cache_artifact(
                    manifest_hash,
                    content_fingerprint,
                    manifest.total_size_bytes,
                    generated_at_unix,
                    err.to_string(),
                );
            }
        };
        let format = image::guess_format(&sniff_bytes).ok();

        if let Some(format) = format {
            if image_format_mime_type(format).is_none() {
                return unsupported_media_cache_artifact(
                    manifest_hash,
                    content_fingerprint,
                    manifest.total_size_bytes,
                    generated_at_unix,
                    "media format is not supported for thumbnail extraction",
                );
            }

            let build_permits = self.media_cache_build_config.permits_for_estimated_bytes(
                estimated_image_build_bytes(
                    manifest.total_size_bytes,
                    image_dimensions(&sniff_bytes, format).ok(),
                    include_thumbnail,
                    self.media_cache_build_config.image_limits(),
                ),
            );
            let build_permit = self
                .media_cache_build_permits
                .clone()
                .acquire_many_owned(build_permits)
                .await
                .expect("media cache build semaphore should remain open");

            let manifest_owned = manifest.clone();
            let chunks_dir = self.chunks_dir.clone();
            let manifest_hash_owned = manifest_hash.to_string();
            let content_fingerprint_owned = content_fingerprint.to_string();
            let image_limits = self.media_cache_build_config.image_limits().clone();

            return match task::spawn_blocking(move || {
                let _build_permit = build_permit;
                build_image_media_cache_blocking(
                    &manifest_hash_owned,
                    &content_fingerprint_owned,
                    &manifest_owned,
                    &chunks_dir,
                    include_thumbnail,
                    &image_limits,
                )
            })
            .await
            {
                Ok(Ok(derived)) => derived,
                Ok(Err(err)) => failed_media_cache_artifact(
                    manifest_hash,
                    content_fingerprint,
                    manifest.total_size_bytes,
                    generated_at_unix,
                    err.to_string(),
                ),
                Err(err) => failed_media_cache_artifact(
                    manifest_hash,
                    content_fingerprint,
                    manifest.total_size_bytes,
                    generated_at_unix,
                    format!("image media cache task failed: {err}"),
                ),
            };
        }

        let _build_permit = self
            .media_cache_build_permits
            .clone()
            .acquire_many_owned(
                self.media_cache_build_config
                    .permits_for_source_size(manifest.total_size_bytes),
            )
            .await
            .expect("media cache build semaphore should remain open");

        match derive_video_media_cache(
            manifest_hash,
            content_fingerprint,
            manifest.total_size_bytes,
            manifest,
            &self.chunks_dir,
            &self.media_tools,
            include_thumbnail,
        )
        .await
        {
            Ok(derived) => derived,
            Err(err) => failed_media_cache_artifact(
                manifest_hash,
                content_fingerprint,
                manifest.total_size_bytes,
                generated_at_unix,
                err.to_string(),
            ),
        }
    }

    async fn persist_media_cache_record(&self, derived: &DerivedMediaCacheArtifact) -> Result<()> {
        persist_media_cache_record_with_payload(
            &self.media_thumbnails_dir,
            self.metadata_store.as_ref(),
            &derived.metadata,
            derived.thumbnail_payload.as_deref(),
        )
        .await
    }
}

fn base_media_metadata(
    manifest_hash: &str,
    content_fingerprint: &str,
    source_size_bytes: usize,
    generated_at_unix: u64,
) -> CachedMediaMetadata {
    CachedMediaMetadata {
        schema_version: MEDIA_CACHE_SCHEMA_VERSION,
        content_fingerprint: content_fingerprint.to_string(),
        source_manifest_hash: manifest_hash.to_string(),
        status: MediaCacheStatus::Failed,
        media_type: None,
        mime_type: None,
        width: None,
        height: None,
        orientation: None,
        taken_at_unix: None,
        gps: None,
        thumbnail: None,
        source_size_bytes,
        generated_at_unix,
        retry_after_unix: None,
        error: None,
    }
}

pub fn media_cache_incomplete_retry_after_unix(now_unix: u64) -> u64 {
    now_unix.saturating_add(media_cache_incomplete_retry_secs())
}

fn media_cache_incomplete_retry_secs() -> u64 {
    std::env::var(MEDIA_CACHE_INCOMPLETE_RETRY_SECS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(MEDIA_CACHE_INCOMPLETE_RETRY_SECS)
}

fn incomplete_media_cache_artifact(
    manifest_hash: &str,
    content_fingerprint: &str,
    source_size_bytes: usize,
    generated_at_unix: u64,
    error: impl Into<String>,
) -> DerivedMediaCacheArtifact {
    DerivedMediaCacheArtifact {
        metadata: CachedMediaMetadata {
            status: MediaCacheStatus::Incomplete,
            retry_after_unix: Some(media_cache_incomplete_retry_after_unix(generated_at_unix)),
            error: Some(error.into()),
            ..base_media_metadata(
                manifest_hash,
                content_fingerprint,
                source_size_bytes,
                generated_at_unix,
            )
        },
        thumbnail_payload: None,
    }
}

pub fn promote_cached_media_metadata_to_incomplete(
    metadata: &CachedMediaMetadata,
    generated_at_unix: u64,
    error: impl Into<String>,
) -> CachedMediaMetadata {
    preserve_cached_media_metadata_status(
        metadata,
        MediaCacheStatus::Incomplete,
        generated_at_unix,
        error,
        Some(media_cache_incomplete_retry_after_unix(generated_at_unix)),
    )
}

fn preserve_cached_media_metadata_status(
    metadata: &CachedMediaMetadata,
    status: MediaCacheStatus,
    generated_at_unix: u64,
    error: impl Into<String>,
    retry_after_unix: Option<u64>,
) -> CachedMediaMetadata {
    let mut next = metadata.clone();
    next.status = status;
    next.thumbnail = None;
    next.generated_at_unix = generated_at_unix;
    next.retry_after_unix = retry_after_unix;
    next.error = Some(error.into());
    next
}

fn merge_cached_media_metadata_without_thumbnail(
    existing: &CachedMediaMetadata,
    derived: &CachedMediaMetadata,
) -> CachedMediaMetadata {
    let (status, retry_after_unix, fallback_error) = match derived.status {
        MediaCacheStatus::Incomplete => (
            MediaCacheStatus::Incomplete,
            Some(media_cache_incomplete_retry_after_unix(
                derived.generated_at_unix,
            )),
            "media source is incomplete locally; one or more chunks are missing or have the wrong size",
        ),
        MediaCacheStatus::Unsupported => (
            MediaCacheStatus::Unsupported,
            None,
            "media format is not supported for thumbnail extraction",
        ),
        MediaCacheStatus::Failed => (
            MediaCacheStatus::Failed,
            None,
            "thumbnail generation failed",
        ),
        MediaCacheStatus::Ready => (
            MediaCacheStatus::Failed,
            None,
            "media thumbnail build finished without producing a thumbnail",
        ),
    };

    preserve_cached_media_metadata_status(
        existing,
        status,
        derived.generated_at_unix,
        derived
            .error
            .clone()
            .unwrap_or_else(|| fallback_error.to_string()),
        retry_after_unix,
    )
}

pub fn media_cache_retry_due(metadata: &CachedMediaMetadata, now_unix: u64) -> bool {
    metadata.status == MediaCacheStatus::Incomplete
        && metadata
            .retry_after_unix
            .map(|retry_after_unix| retry_after_unix <= now_unix)
            .unwrap_or(true)
}

fn positive_env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn positive_env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn failed_media_cache_artifact(
    manifest_hash: &str,
    content_fingerprint: &str,
    source_size_bytes: usize,
    generated_at_unix: u64,
    error: impl Into<String>,
) -> DerivedMediaCacheArtifact {
    DerivedMediaCacheArtifact {
        metadata: CachedMediaMetadata {
            status: MediaCacheStatus::Failed,
            error: Some(error.into()),
            ..base_media_metadata(
                manifest_hash,
                content_fingerprint,
                source_size_bytes,
                generated_at_unix,
            )
        },
        thumbnail_payload: None,
    }
}

fn unsupported_media_cache_artifact(
    manifest_hash: &str,
    content_fingerprint: &str,
    source_size_bytes: usize,
    generated_at_unix: u64,
    error: impl Into<String>,
) -> DerivedMediaCacheArtifact {
    DerivedMediaCacheArtifact {
        metadata: CachedMediaMetadata {
            status: MediaCacheStatus::Unsupported,
            error: Some(error.into()),
            ..base_media_metadata(
                manifest_hash,
                content_fingerprint,
                source_size_bytes,
                generated_at_unix,
            )
        },
        thumbnail_payload: None,
    }
}

pub(super) async fn persist_media_cache_record_with_payload(
    media_thumbnails_dir: &Path,
    metadata_store: &dyn MetadataStore,
    metadata: &CachedMediaMetadata,
    thumbnail_payload: Option<&[u8]>,
) -> Result<()> {
    if let (Some(thumbnail), Some(payload)) = (&metadata.thumbnail, thumbnail_payload) {
        let thumbnail_path = media_thumbnails_dir
            .join(&metadata.content_fingerprint)
            .join(format!("{}.jpg", thumbnail.profile));
        write_atomic(&thumbnail_path, payload).await?;
    }
    metadata_store.persist_media_cache_record(metadata).await
}

async fn manifest_chunks_are_locally_complete(
    manifest: &ObjectManifest,
    chunks_dir: &Path,
) -> Result<bool> {
    for chunk in &manifest.chunks {
        let chunk_path = chunk_path_for_hash(chunks_dir, &chunk.hash)?;
        let metadata = match fs::metadata(&chunk_path).await {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        if metadata.len() != chunk.size_bytes as u64 {
            return Ok(false);
        }
    }

    Ok(true)
}

async fn read_object_prefix_from_manifest(
    manifest: &ObjectManifest,
    chunks_dir: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let target_len = std::cmp::min(manifest.total_size_bytes, max_bytes);
    let mut prefix = Vec::with_capacity(target_len);

    for chunk in &manifest.chunks {
        if prefix.len() >= target_len {
            break;
        }

        let chunk_path = chunk_path_for_hash(chunks_dir, &chunk.hash)?;
        let payload = fs::read(&chunk_path)
            .await
            .with_context(|| format!("failed reading chunk {}", chunk.hash))?;
        if payload.len() != chunk.size_bytes {
            bail!(
                "size mismatch for chunk hash={} expected={} actual={}",
                chunk.hash,
                chunk.size_bytes,
                payload.len()
            );
        }
        let actual_hash = hash_hex(&payload);
        if actual_hash != chunk.hash {
            bail!(
                "hash mismatch for chunk expected={} actual={}",
                chunk.hash,
                actual_hash
            );
        }

        let remaining = target_len.saturating_sub(prefix.len());
        prefix.extend_from_slice(&payload[..remaining.min(payload.len())]);
    }

    Ok(prefix)
}

async fn collect_local_chunk_paths(
    manifest: &ObjectManifest,
    chunks_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::with_capacity(manifest.chunks.len());
    for chunk in &manifest.chunks {
        let chunk_path = chunk_path_for_hash(chunks_dir, &chunk.hash)?;
        let metadata = fs::metadata(&chunk_path)
            .await
            .with_context(|| format!("missing chunk {}", chunk.hash))?;
        if metadata.len() != chunk.size_bytes as u64 {
            bail!(
                "size mismatch for chunk hash={} expected={} actual={}",
                chunk.hash,
                chunk.size_bytes,
                metadata.len()
            );
        }
        paths.push(chunk_path);
    }
    Ok(paths)
}

/// Holds the chunk hashes and precomputed byte offsets for a virtual video file.
/// Paths are reconstructed from `chunks_dir` + hash at read time rather than
/// stored, so the read path is always rooted in the trusted chunks directory.
struct ChunkVideoIndex {
    chunks_dir: PathBuf,
    hashes: Vec<String>,
    /// Byte offset of each chunk's first byte in the virtual file.
    offsets: Vec<u64>,
    total_size: u64,
}

impl ChunkVideoIndex {
    fn new(chunks_dir: PathBuf, manifest: &ObjectManifest) -> Self {
        let mut offsets = Vec::with_capacity(manifest.chunks.len());
        let mut offset = 0u64;
        for chunk in &manifest.chunks {
            offsets.push(offset);
            offset += chunk.size_bytes as u64;
        }
        let hashes = manifest.chunks.iter().map(|c| c.hash.clone()).collect();
        Self {
            chunks_dir,
            hashes,
            offsets,
            total_size: offset,
        }
    }

    async fn read_range(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        for i in 0..self.hashes.len() {
            let chunk_start = self.offsets[i];
            let chunk_size = if i + 1 < self.offsets.len() {
                self.offsets[i + 1] - chunk_start
            } else {
                self.total_size - chunk_start
            };
            let chunk_end = chunk_start + chunk_size.saturating_sub(1);
            if chunk_end < start {
                continue;
            }
            if chunk_start > end {
                break;
            }
            let read_from = start.saturating_sub(chunk_start) as usize;
            let read_to = (end.min(chunk_end) - chunk_start) as usize;
            let path = chunk_path_for_hash(&self.chunks_dir, &self.hashes[i])?;
            let data = fs::read(&path).await?;
            result.extend_from_slice(&data[read_from..=read_to]);
        }
        Ok(result)
    }
}

async fn serve_video_range(
    State(index): State<Arc<ChunkVideoIndex>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let total = index.total_size;
    let (start, end, partial) = match headers.get(header::RANGE) {
        Some(v) => match parse_http_byte_range(v.to_str().unwrap_or(""), total) {
            Some((s, e)) => (s, e, true),
            None => {
                return (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [(
                        header::CONTENT_RANGE,
                        format!("bytes */{total}")
                            .parse::<axum::http::HeaderValue>()
                            .unwrap(),
                    )],
                    axum::body::Body::empty(),
                )
                    .into_response();
            }
        },
        None => (0, total.saturating_sub(1), false),
    };

    match index.read_range(start, end).await {
        Ok(data) => {
            let len = data.len();
            let status = if partial {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let mut builder = axum::response::Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_LENGTH, len);
            if partial {
                builder = builder.header(
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{total}"),
                );
            }
            builder
                .body(axum::body::Body::from(data))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(err) => {
            warn!(?err, "chunk video server: range read failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn parse_http_byte_range(range: &str, total: u64) -> Option<(u64, u64)> {
    let s = range.strip_prefix("bytes=")?;
    if let Some(suffix) = s.strip_prefix('-') {
        let n: u64 = suffix.trim().parse().ok()?;
        if n == 0 || total == 0 {
            return None;
        }
        Some((total.saturating_sub(n), total - 1))
    } else {
        let (a, b) = s.split_once('-')?;
        let start: u64 = a.trim().parse().ok()?;
        let end = if b.trim().is_empty() {
            total.saturating_sub(1)
        } else {
            b.trim().parse::<u64>().ok()?.min(total.saturating_sub(1))
        };
        (start <= end && start < total).then_some((start, end))
    }
}

/// Starts a local HTTP server on 127.0.0.1 that presents the chunked video
/// as a single seekable file via Range requests.
///
/// A random UUID token is embedded as a literal route segment so that other
/// local processes cannot reach the endpoint without knowing the token.
/// The server is torn down (task aborted) as soon as ffprobe/ffmpeg finish.
async fn start_chunk_video_server(
    index: Arc<ChunkVideoIndex>,
    _temp_dir: &Path,
) -> Result<(tokio::task::JoinHandle<()>, String)> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind local TCP listener for chunk video server")?;
    let port = listener.local_addr()?.port();
    let token = Uuid::new_v4().to_string();
    let route = format!("/{token}/video");

    let app = Router::new()
        .route(&route, axum::routing::get(serve_video_range))
        .with_state(index);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let url = format!("http://127.0.0.1:{port}/{token}/video");
    Ok((handle, url))
}

async fn derive_video_media_cache(
    manifest_hash: &str,
    content_fingerprint: &str,
    source_size_bytes: usize,
    manifest: &ObjectManifest,
    chunks_dir: &Path,
    media_tools: &MediaToolPaths,
    include_thumbnail: bool,
) -> Result<DerivedMediaCacheArtifact> {
    let generated_at_unix = unix_ts();
    // Validate all chunks are present and have the expected size.
    collect_local_chunk_paths(manifest, chunks_dir).await?;
    let chunk_index = Arc::new(ChunkVideoIndex::new(chunks_dir.to_path_buf(), manifest));

    let temp_dir = std::env::temp_dir().join(format!("ironmesh-media-cache-{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir)
        .await
        .with_context(|| format!("failed to create temp dir {}", temp_dir.display()))?;

    let (server_task, video_url) = match start_chunk_video_server(chunk_index, &temp_dir).await {
        Ok(v) => v,
        Err(err) => {
            let _ = fs::remove_dir_all(&temp_dir).await;
            return Err(err);
        }
    };

    let derived = async {
        let mut ffprobe = Command::new(&media_tools.ffprobe);
        ffprobe
            .arg("-v")
            .arg("error")
            .arg("-select_streams")
            .arg("v:0")
            .arg("-show_entries")
            .arg("stream=width,height,codec_name:format=format_name,duration")
            .arg("-of")
            .arg("json")
            .arg(&video_url);
        let probe_output = run_media_tool(&mut ffprobe, FFPROBE_TIMEOUT_SECS, "ffprobe").await?;
        let probe: FfprobeOutput = serde_json::from_slice(&probe_output.stdout)
            .context("failed to parse ffprobe JSON output")?;
        let Some(stream) = probe.streams.first() else {
            return Ok::<DerivedMediaCacheArtifact, anyhow::Error>(
                unsupported_media_cache_artifact(
                    manifest_hash,
                    content_fingerprint,
                    source_size_bytes,
                    generated_at_unix,
                    "unsupported media format",
                ),
            );
        };

        let mime_type = video_mime_type_for_format_name(
            probe
                .format
                .as_ref()
                .and_then(|format| format.format_name.as_deref()),
        );
        let metadata = CachedMediaMetadata {
            status: MediaCacheStatus::Ready,
            media_type: Some("video".to_string()),
            mime_type,
            width: stream.width,
            height: stream.height,
            ..base_media_metadata(
                manifest_hash,
                content_fingerprint,
                source_size_bytes,
                generated_at_unix,
            )
        };

        if !include_thumbnail {
            return Ok(DerivedMediaCacheArtifact {
                metadata,
                thumbnail_payload: None,
            });
        }

        let duration_secs = probe
            .format
            .as_ref()
            .and_then(|format| format.duration.as_deref())
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite() && *value > 0.0);

        let mut ffmpeg = Command::new(&media_tools.ffmpeg);
        ffmpeg.arg("-v").arg("error").arg("-nostdin");
        if let Some(seek_time) = preferred_video_seek_time(duration_secs) {
            ffmpeg.arg("-ss").arg(seek_time);
        }
        ffmpeg
            .arg("-i")
            .arg(&video_url)
            .arg("-an")
            .arg("-sn")
            .arg("-dn")
            .arg("-vf")
            .arg(format!(
                "thumbnail=100,scale={0}:{0}:force_original_aspect_ratio=decrease",
                GRID_THUMBNAIL_MAX_DIMENSION
            ))
            .arg("-frames:v")
            .arg("1")
            .arg("-f")
            .arg("image2pipe")
            .arg("-vcodec")
            .arg("mjpeg")
            .arg("pipe:1");
        let ffmpeg_output = run_media_tool(&mut ffmpeg, FFMPEG_TIMEOUT_SECS, "ffmpeg").await?;
        let rendered = image::load_from_memory(&ffmpeg_output.stdout)
            .context("failed to decode ffmpeg thumbnail output")?;

        Ok(DerivedMediaCacheArtifact {
            metadata: CachedMediaMetadata {
                thumbnail: Some(CachedThumbnailInfo {
                    profile: GRID_THUMBNAIL_PROFILE.to_string(),
                    format: "jpeg".to_string(),
                    width: rendered.width(),
                    height: rendered.height(),
                    size_bytes: ffmpeg_output.stdout.len() as u64,
                }),
                ..metadata
            },
            thumbnail_payload: Some(ffmpeg_output.stdout),
        })
    }
    .await;

    server_task.abort();
    let _ = fs::remove_dir_all(&temp_dir).await;
    derived
}

async fn run_media_tool(
    command: &mut Command,
    timeout_secs: u64,
    tool_name: &str,
) -> Result<std::process::Output> {
    command.kill_on_drop(true);
    match timeout(Duration::from_secs(timeout_secs), command.output()).await {
        Ok(Ok(output)) if output.status.success() => Ok(output),
        Ok(Ok(output)) => {
            bail!(
                "{tool_name} exited with status {}: {}",
                output.status,
                trimmed_command_output(&output.stderr)
            )
        }
        Ok(Err(err)) => Err(err).with_context(|| format!("failed to spawn {tool_name}")),
        Err(_) => bail!("{tool_name} timed out after {timeout_secs}s"),
    }
}

fn trimmed_command_output(stderr: &[u8]) -> String {
    let value = String::from_utf8_lossy(stderr).trim().to_string();
    if value.len() > 400 {
        format!("{}...", &value[..400])
    } else if value.is_empty() {
        "<no stderr output>".to_string()
    } else {
        value
    }
}

pub(super) fn preferred_video_seek_time(duration_secs: Option<f64>) -> Option<String> {
    let seek = match duration_secs {
        Some(duration_secs) => (duration_secs * VIDEO_THUMBNAIL_SEEK_FRACTION)
            .clamp(VIDEO_THUMBNAIL_SEEK_MIN_SECS, VIDEO_THUMBNAIL_SEEK_MAX_SECS)
            .min(duration_secs),
        None => VIDEO_THUMBNAIL_UNKNOWN_DURATION_SEEK_SECS,
    };
    Some(format!("{seek:.3}"))
}

fn video_mime_type_for_format_name(format_name: Option<&str>) -> Option<String> {
    let format_name = format_name?;
    if format_name.contains("webm") {
        return Some("video/webm".to_string());
    }
    if format_name.contains("matroska") {
        return Some("video/x-matroska".to_string());
    }
    if format_name.contains("mov") || format_name.contains("mp4") || format_name.contains("3gp") {
        return Some("video/mp4".to_string());
    }
    if format_name.contains("avi") {
        return Some("video/x-msvideo".to_string());
    }
    if format_name.contains("flv") {
        return Some("video/x-flv".to_string());
    }
    if format_name.contains("mpegts") || format_name == "ts" {
        return Some("video/mp2t".to_string());
    }
    if format_name.contains("ogg") {
        return Some("video/ogg".to_string());
    }
    if format_name.contains("mpeg") {
        return Some("video/mpeg".to_string());
    }
    None
}

fn build_image_media_cache_blocking(
    manifest_hash: &str,
    content_fingerprint: &str,
    manifest: &ObjectManifest,
    chunks_dir: &Path,
    include_thumbnail: bool,
    image_limits: &MediaCacheImageLimits,
) -> Result<DerivedMediaCacheArtifact> {
    let payload = read_object_by_manifest_blocking(manifest, chunks_dir)?;
    derive_image_media_cache(
        manifest_hash,
        content_fingerprint,
        manifest.total_size_bytes,
        &payload,
        include_thumbnail,
        image_limits,
    )
}

fn read_object_by_manifest_blocking(
    manifest: &ObjectManifest,
    chunks_dir: &Path,
) -> Result<Vec<u8>> {
    let mut assembled = Vec::new();

    for chunk in &manifest.chunks {
        let chunk_path = chunk_path_for_hash(chunks_dir, &chunk.hash)?;
        let payload = std::fs::read(&chunk_path)
            .with_context(|| format!("failed reading chunk {}", chunk.hash))?;

        if payload.len() != chunk.size_bytes {
            bail!(
                "size mismatch for chunk hash={} expected={} actual={}",
                chunk.hash,
                chunk.size_bytes,
                payload.len()
            );
        }

        let actual_hash = hash_hex(&payload);
        if actual_hash != chunk.hash {
            bail!(
                "hash mismatch for chunk expected={} actual={}",
                chunk.hash,
                actual_hash
            );
        }

        assembled.reserve(payload.len());
        assembled.extend_from_slice(&payload);
    }

    if assembled.len() != manifest.total_size_bytes {
        bail!(
            "assembled payload size mismatch key={} expected={} actual={}",
            manifest.key,
            manifest.total_size_bytes,
            assembled.len()
        );
    }

    Ok(assembled)
}

fn derive_image_media_cache(
    manifest_hash: &str,
    content_fingerprint: &str,
    source_size_bytes: usize,
    payload: &[u8],
    include_thumbnail: bool,
    image_limits: &MediaCacheImageLimits,
) -> Result<DerivedMediaCacheArtifact> {
    let generated_at_unix = unix_ts();
    let format = match image::guess_format(payload) {
        Ok(format) => format,
        Err(_) => {
            return Ok(unsupported_media_cache_artifact(
                manifest_hash,
                content_fingerprint,
                source_size_bytes,
                generated_at_unix,
                "unsupported media format",
            ));
        }
    };

    let mime_type = match image_format_mime_type(format) {
        Some(value) => value.to_string(),
        None => {
            return Ok(unsupported_media_cache_artifact(
                manifest_hash,
                content_fingerprint,
                source_size_bytes,
                generated_at_unix,
                "media format is not supported for thumbnail extraction",
            ));
        }
    };

    let (width, height) = image_dimensions(payload, format)?;
    let (orientation, gps, taken_at_unix) = extract_exif_fields(payload);
    let mut metadata = CachedMediaMetadata {
        status: MediaCacheStatus::Ready,
        media_type: Some("image".to_string()),
        mime_type: Some(mime_type),
        width: Some(width),
        height: Some(height),
        orientation,
        taken_at_unix,
        gps,
        ..base_media_metadata(
            manifest_hash,
            content_fingerprint,
            source_size_bytes,
            generated_at_unix,
        )
    };

    if !include_thumbnail {
        return Ok(DerivedMediaCacheArtifact {
            metadata,
            thumbnail_payload: None,
        });
    }

    if let Some(error) = validate_image_decode_limits(width, height, image_limits) {
        metadata.status = MediaCacheStatus::Unsupported;
        metadata.error = Some(error);
        return Ok(DerivedMediaCacheArtifact {
            metadata,
            thumbnail_payload: None,
        });
    }

    let image = decode_image_with_limits(payload, format, image_limits)?;
    let rendered_thumbnail = render_thumbnail(image, orientation, GRID_THUMBNAIL_MAX_DIMENSION)?;

    metadata.thumbnail = Some(CachedThumbnailInfo {
        profile: GRID_THUMBNAIL_PROFILE.to_string(),
        format: "jpeg".to_string(),
        width: rendered_thumbnail.width,
        height: rendered_thumbnail.height,
        size_bytes: rendered_thumbnail.payload.len() as u64,
    });

    Ok(DerivedMediaCacheArtifact {
        metadata,
        thumbnail_payload: Some(rendered_thumbnail.payload),
    })
}

fn image_format_mime_type(format: ImageFormat) -> Option<&'static str> {
    match format {
        ImageFormat::Bmp => Some("image/bmp"),
        ImageFormat::Gif => Some("image/gif"),
        ImageFormat::Jpeg => Some("image/jpeg"),
        ImageFormat::Png => Some("image/png"),
        ImageFormat::WebP => Some("image/webp"),
        _ => None,
    }
}

pub(crate) fn current_media_cache_metadata(
    metadata: Option<CachedMediaMetadata>,
) -> Option<CachedMediaMetadata> {
    metadata.filter(|metadata| metadata.schema_version == MEDIA_CACHE_SCHEMA_VERSION)
}

fn image_dimensions(payload: &[u8], format: ImageFormat) -> Result<(u32, u32)> {
    ImageReader::with_format(Cursor::new(payload), format)
        .into_dimensions()
        .context("failed to inspect image dimensions")
}

fn decode_image_with_limits(
    payload: &[u8],
    format: ImageFormat,
    image_limits: &MediaCacheImageLimits,
) -> Result<DynamicImage> {
    let mut reader = ImageReader::with_format(Cursor::new(payload), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(image_limits.max_dimension);
    limits.max_image_height = Some(image_limits.max_dimension);
    limits.max_alloc = Some(image_limits.max_decode_bytes);
    reader.limits(limits);
    reader.decode().context("failed to decode image payload")
}

fn estimated_image_build_bytes(
    source_size_bytes: usize,
    dimensions: Option<(u32, u32)>,
    include_thumbnail: bool,
    image_limits: &MediaCacheImageLimits,
) -> u64 {
    let source_size_bytes = u64::try_from(source_size_bytes).unwrap_or(u64::MAX);
    if !include_thumbnail {
        return source_size_bytes;
    }

    let decode_bytes = dimensions
        .map(|(width, height)| {
            u64::from(width)
                .saturating_mul(u64::from(height))
                .saturating_mul(IMAGE_DECODE_ESTIMATED_BYTES_PER_PIXEL)
        })
        .unwrap_or_else(|| {
            image_limits.max_decode_bytes.max(
                image_limits
                    .max_pixels
                    .saturating_mul(IMAGE_DECODE_ESTIMATED_BYTES_PER_PIXEL),
            )
        });

    decode_bytes.max(source_size_bytes)
}

fn validate_image_decode_limits(
    width: u32,
    height: u32,
    image_limits: &MediaCacheImageLimits,
) -> Option<String> {
    if width > image_limits.max_dimension || height > image_limits.max_dimension {
        return Some(format!(
            "image thumbnail generation rejected: dimensions {}x{} exceed limit {}px",
            width, height, image_limits.max_dimension
        ));
    }

    let pixel_count = u64::from(width).saturating_mul(u64::from(height));
    if pixel_count > image_limits.max_pixels {
        return Some(format!(
            "image thumbnail generation rejected: pixel count {} exceeds limit {}",
            pixel_count, image_limits.max_pixels
        ));
    }

    let estimated_decode_bytes = pixel_count.saturating_mul(IMAGE_DECODE_ESTIMATED_BYTES_PER_PIXEL);
    if estimated_decode_bytes > image_limits.max_decode_bytes {
        return Some(format!(
            "image thumbnail generation rejected: estimated decode footprint {} bytes exceeds limit {} bytes",
            estimated_decode_bytes, image_limits.max_decode_bytes
        ));
    }

    None
}

fn render_thumbnail(
    mut image: DynamicImage,
    orientation: Option<u16>,
    max_dimension: u32,
) -> Result<RenderedThumbnail> {
    apply_exif_orientation(&mut image, orientation);
    let thumbnail = image.thumbnail(max_dimension, max_dimension);
    let mut encoded = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut encoded, 82);
    encoder
        .encode_image(&thumbnail)
        .context("failed to encode thumbnail")?;
    Ok(RenderedThumbnail {
        payload: encoded,
        width: thumbnail.width(),
        height: thumbnail.height(),
    })
}

fn apply_exif_orientation(image: &mut DynamicImage, orientation: Option<u16>) {
    let Some(orientation) = orientation
        .and_then(|value| u8::try_from(value).ok())
        .and_then(Orientation::from_exif)
    else {
        return;
    };
    image.apply_orientation(orientation);
}

fn extract_exif_fields(payload: &[u8]) -> (Option<u16>, Option<MediaGpsCoordinates>, Option<u64>) {
    let mut cursor = Cursor::new(payload);
    let exif = match ExifReader::new().read_from_container(&mut cursor) {
        Ok(value) => value,
        Err(_) => return (None, None, None),
    };

    let orientation = exif
        .get_field(Tag::Orientation, In::PRIMARY)
        .and_then(|field| field.value.get_uint(0))
        .and_then(|value| u16::try_from(value).ok());

    let latitude = exif
        .get_field(Tag::GPSLatitude, In::PRIMARY)
        .and_then(|field| exif_gps_coordinate(&field.value))
        .map(
            |value| match exif_ascii_ref(exif.get_field(Tag::GPSLatitudeRef, In::PRIMARY)) {
                Some('S') | Some('s') => -value,
                _ => value,
            },
        );
    let longitude = exif
        .get_field(Tag::GPSLongitude, In::PRIMARY)
        .and_then(|field| exif_gps_coordinate(&field.value))
        .map(
            |value| match exif_ascii_ref(exif.get_field(Tag::GPSLongitudeRef, In::PRIMARY)) {
                Some('W') | Some('w') => -value,
                _ => value,
            },
        );

    let gps = match (latitude, longitude) {
        (Some(latitude), Some(longitude)) => Some(MediaGpsCoordinates {
            latitude,
            longitude,
        }),
        _ => None,
    };

    let taken_at_unix = exif_taken_at_unix(&exif);

    (orientation, gps, taken_at_unix)
}

fn exif_taken_at_unix(exif: &exif::Exif) -> Option<u64> {
    parse_exif_taken_at(
        exif_ascii_string(exif.get_field(Tag::DateTimeOriginal, In::PRIMARY)),
        exif_ascii_string(exif.get_field(Tag::OffsetTimeOriginal, In::PRIMARY))
            .or_else(|| exif_ascii_string(exif.get_field(Tag::OffsetTime, In::PRIMARY))),
    )
    .or_else(|| {
        parse_exif_taken_at(
            exif_ascii_string(exif.get_field(Tag::DateTimeDigitized, In::PRIMARY)),
            exif_ascii_string(exif.get_field(Tag::OffsetTimeDigitized, In::PRIMARY))
                .or_else(|| exif_ascii_string(exif.get_field(Tag::OffsetTime, In::PRIMARY))),
        )
    })
    .or_else(|| {
        parse_exif_taken_at(
            exif_ascii_string(exif.get_field(Tag::DateTime, In::PRIMARY)),
            exif_ascii_string(exif.get_field(Tag::OffsetTime, In::PRIMARY)),
        )
    })
}

pub(super) fn parse_exif_taken_at(datetime: Option<&str>, offset: Option<&str>) -> Option<u64> {
    let date_time = parse_exif_datetime(datetime?)?;
    let timestamp = match offset.and_then(parse_exif_offset) {
        Some(offset) => date_time.assume_offset(offset).unix_timestamp(),
        None => date_time.assume_utc().unix_timestamp(),
    };
    u64::try_from(timestamp).ok()
}

fn parse_exif_datetime(value: &str) -> Option<PrimitiveDateTime> {
    let value = value.get(..19)?;
    if !matches!(value.as_bytes().get(4), Some(b':'))
        || !matches!(value.as_bytes().get(7), Some(b':'))
        || !matches!(value.as_bytes().get(10), Some(b' '))
        || !matches!(value.as_bytes().get(13), Some(b':'))
        || !matches!(value.as_bytes().get(16), Some(b':'))
    {
        return None;
    }

    let year = value.get(0..4)?.parse::<i32>().ok()?;
    let month = value.get(5..7)?.parse::<u8>().ok()?;
    let day = value.get(8..10)?.parse::<u8>().ok()?;
    let hour = value.get(11..13)?.parse::<u8>().ok()?;
    let minute = value.get(14..16)?.parse::<u8>().ok()?;
    let second = value.get(17..19)?.parse::<u8>().ok()?;

    let month = Month::try_from(month).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    Some(PrimitiveDateTime::new(date, time))
}

fn parse_exif_offset(value: &str) -> Option<UtcOffset> {
    let value = value.get(..6)?;
    if !matches!(value.as_bytes().first(), Some(b'+') | Some(b'-'))
        || !matches!(value.as_bytes().get(3), Some(b':'))
    {
        return None;
    }

    let sign = if value.starts_with('-') { -1 } else { 1 };
    let hours = value.get(1..3)?.parse::<i8>().ok()?;
    let minutes = value.get(4..6)?.parse::<i8>().ok()?;
    UtcOffset::from_hms(sign * hours, sign * minutes, 0).ok()
}

fn exif_ascii_string(field: Option<&exif::Field>) -> Option<&str> {
    match &field?.value {
        Value::Ascii(values) => {
            let value = values.first()?;
            let value = std::str::from_utf8(value).ok()?;
            let value = value.trim_matches(char::from(0)).trim();
            if value.is_empty() { None } else { Some(value) }
        }
        _ => None,
    }
}

fn exif_ascii_ref(field: Option<&exif::Field>) -> Option<char> {
    exif_ascii_string(field)?.chars().next()
}

pub(super) fn exif_gps_coordinate(value: &Value) -> Option<f64> {
    match value {
        Value::Rational(values) if values.len() >= 3 => {
            let degrees = values[0].to_f64();
            let minutes = values[1].to_f64();
            let seconds = values[2].to_f64();
            if !degrees.is_finite() || !minutes.is_finite() || !seconds.is_finite() {
                return None;
            }
            let total = degrees + (minutes / 60.0) + (seconds / 3600.0);
            total.is_finite().then_some(total)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_png_bytes() -> Vec<u8> {
        let image = image::DynamicImage::new_rgba8(4, 3);
        let mut cursor = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut cursor, image::ImageFormat::Png)
            .unwrap();
        cursor.into_inner()
    }

    #[test]
    fn media_cache_build_config_scales_permits_by_source_size() {
        let config = MediaCacheBuildConfig {
            total_permits: 20,
            bytes_per_permit: 16 * 1024 * 1024,
            image_limits: MediaCacheImageLimits::default(),
        };

        assert_eq!(config.permits_for_source_size(0), 1);
        assert_eq!(config.permits_for_source_size(1), 1);
        assert_eq!(config.permits_for_source_size(16 * 1024 * 1024), 1);
        assert_eq!(config.permits_for_source_size((16 * 1024 * 1024) + 1), 2);
        assert_eq!(
            config.permits_for_source_size(usize::MAX),
            config.total_permits
        );
    }

    #[test]
    fn derive_image_media_cache_only_applies_decode_limits_for_thumbnail_builds() {
        let payload = sample_png_bytes();
        let image_limits = MediaCacheImageLimits {
            max_dimension: 10,
            max_pixels: 11,
            max_decode_bytes: 1024 * 1024,
        };

        let metadata_only = derive_image_media_cache(
            "manifest",
            "fingerprint",
            payload.len(),
            &payload,
            false,
            &image_limits,
        )
        .unwrap();
        assert_eq!(metadata_only.metadata.status, MediaCacheStatus::Ready);
        assert_eq!(metadata_only.metadata.width, Some(4));
        assert_eq!(metadata_only.metadata.height, Some(3));
        assert!(metadata_only.metadata.thumbnail.is_none());

        let with_thumbnail = derive_image_media_cache(
            "manifest",
            "fingerprint",
            payload.len(),
            &payload,
            true,
            &image_limits,
        )
        .unwrap();
        assert_eq!(
            with_thumbnail.metadata.status,
            MediaCacheStatus::Unsupported
        );
        assert_eq!(with_thumbnail.metadata.width, Some(4));
        assert_eq!(with_thumbnail.metadata.height, Some(3));
        assert!(with_thumbnail.metadata.thumbnail.is_none());
        assert!(with_thumbnail.thumbnail_payload.is_none());
        assert!(
            with_thumbnail
                .metadata
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("pixel count")
        );
    }

    #[test]
    fn estimated_image_build_bytes_uses_conservative_budget_without_dimensions() {
        let image_limits = MediaCacheImageLimits {
            max_dimension: 4_096,
            max_pixels: 40_000_000,
            max_decode_bytes: 256 * 1024 * 1024,
        };

        assert_eq!(
            estimated_image_build_bytes(32 * 1024, None, true, &image_limits),
            image_limits
                .max_decode_bytes
                .max(image_limits.max_pixels * IMAGE_DECODE_ESTIMATED_BYTES_PER_PIXEL)
        );
    }
}
