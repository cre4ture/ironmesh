use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use common::NodeId;
use exif::{In, Reader as ExifReader, Tag, Value};
use image::codecs::jpeg::JpegEncoder;
use image::metadata::Orientation;
use image::{DynamicImage, GenericImageView, ImageFormat};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};
use uuid::Uuid;

mod sqlite_impl;
#[cfg(feature = "turso-metadata")]
mod turso_impl;

use self::sqlite_impl::SqliteMetadataStore;
#[cfg(feature = "turso-metadata")]
use self::turso_impl::TursoMetadataStore;

const CHUNK_SIZE: usize = 1024 * 1024;
pub(crate) const TOMBSTONE_MANIFEST_HASH: &str = "__tombstone__";
const MEDIA_CACHE_SCHEMA_VERSION: u32 = 2;
const GRID_THUMBNAIL_MAX_DIMENSION: u32 = 256;
const GRID_THUMBNAIL_PROFILE: &str = "grid";
const SLOW_STORAGE_WRITE_LOG_THRESHOLD_MS: u128 = 100;
const SLOW_MEDIA_CACHE_LOOKUP_LOG_THRESHOLD_MS: u128 = 250;
const SLOW_MEDIA_CACHE_GENERATION_LOG_THRESHOLD_MS: u128 = 20000;
const READ_THROUGH_CACHE_CLASS: &str = "read_through";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkRef {
    hash: String,
    size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectManifest {
    key: String,
    total_size_bytes: usize,
    chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotManifest {
    id: String,
    created_at_unix: u64,
    objects: HashMap<String, String>,
    #[serde(default)]
    object_ids: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CurrentState {
    objects: HashMap<String, String>,
    #[serde(default)]
    object_ids: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionConsistencyState {
    Provisional,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileVersionRecord {
    version_id: String,
    object_id: String,
    manifest_hash: String,
    #[serde(default)]
    logical_path: Option<String>,
    parent_version_ids: Vec<String>,
    state: VersionConsistencyState,
    created_at_unix: u64,
    copied_from_object_id: Option<String>,
    copied_from_version_id: Option<String>,
    copied_from_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileVersionIndex {
    object_id: String,
    versions: HashMap<String, FileVersionRecord>,
    head_version_ids: Vec<String>,
    preferred_head_version_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionRecordSummary {
    pub version_id: String,
    pub logical_path: Option<String>,
    pub parent_version_ids: Vec<String>,
    pub state: VersionConsistencyState,
    pub created_at_unix: u64,
    pub copied_from_object_id: Option<String>,
    pub copied_from_version_id: Option<String>,
    pub copied_from_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionGraphSummary {
    pub key: String,
    pub object_id: String,
    pub preferred_head_version_id: Option<String>,
    pub preferred_head_reason: Option<PreferredHeadReason>,
    pub head_version_ids: Vec<String>,
    pub versions: Vec<VersionRecordSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMutationResult {
    Applied,
    SourceMissing,
    TargetExists,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstonePathResult {
    pub path: String,
    pub version_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferredHeadReason {
    ConfirmedPreferredOverProvisional,
    ProvisionalFallbackNoConfirmed,
    DeterministicTiebreakVersionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ObjectReadMode {
    #[default]
    Preferred,
    ConfirmedOnly,
    ProvisionalAllowed,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub created_at_unix: u64,
    pub object_count: usize,
}

#[derive(Debug, Clone)]
pub struct SnapshotObjectState {
    pub created_at_unix: u64,
    pub objects: HashMap<String, String>,
    pub object_ids: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageStatsSample {
    pub collected_at_unix: u64,
    pub latest_snapshot_id: Option<String>,
    pub latest_snapshot_created_at_unix: Option<u64>,
    pub latest_snapshot_object_count: usize,
    pub chunk_store_bytes: u64,
    pub manifest_store_bytes: u64,
    pub metadata_db_bytes: u64,
    pub media_cache_bytes: u64,
    pub latest_snapshot_logical_bytes: u64,
    pub latest_snapshot_unique_chunk_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageStatsState {
    pub chunk_store_bytes: u64,
    pub last_reconciled_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedChunkRecord {
    pub(crate) hash: String,
    pub(crate) size_bytes: u64,
    pub(crate) first_cached_unix: u64,
    pub(crate) last_access_unix: u64,
    pub(crate) access_count: u64,
    pub(crate) last_source_node_id: Option<String>,
    pub(crate) cache_class: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupReport {
    pub retention_secs: u64,
    pub dry_run: bool,
    pub protected_manifests: usize,
    pub protected_chunks: usize,
    pub tracked_cached_chunks: usize,
    pub skipped_recent_manifests: usize,
    pub skipped_recent_chunks: usize,
    pub deleted_manifests: usize,
    pub deleted_chunks: usize,
    pub deleted_cached_chunks: usize,
    pub deleted_cached_chunk_records: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TombstoneCompactionReport {
    pub retention_secs: u64,
    pub dry_run: bool,
    pub scanned_indexes: usize,
    pub tombstone_head_indexes: usize,
    pub eligible_indexes: usize,
    pub archived_indexes: usize,
    pub removed_indexes: usize,
    pub archive_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TombstoneArchiveFileInfo {
    pub file_name: String,
    pub path: String,
    pub modified_at_unix: u64,
    pub size_bytes: u64,
    pub entries: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TombstoneRestoreReport {
    pub object_id: String,
    pub source_archive_file: Option<String>,
    pub dry_run: bool,
    pub found: bool,
    pub restored: bool,
    pub skipped_existing: bool,
    pub would_restore: bool,
    pub index_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TombstoneArchivePurgeReport {
    pub retention_secs: u64,
    pub dry_run: bool,
    pub scanned_files: usize,
    pub eligible_files: usize,
    pub deleted_files: usize,
    pub kept_recent_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEvent {
    pub event_id: String,
    pub action: String,
    pub actor: Option<String>,
    pub source_node: Option<String>,
    pub authorized: bool,
    pub dry_run: bool,
    pub approved: bool,
    pub outcome: String,
    pub details_json: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientCredentialState {
    #[serde(default)]
    pub pairing_authorizations: Vec<PairingAuthorizationRecord>,
    #[serde(default)]
    pub credentials: Vec<ClientCredentialRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingAuthorizationRecord {
    pub token_id: String,
    pub pairing_secret_hash: String,
    pub label: Option<String>,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub used_at_unix: Option<u64>,
    pub consumed_by_device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCredentialRecord {
    pub device_id: String,
    pub label: Option<String>,
    #[serde(default)]
    pub public_key_pem: Option<String>,
    #[serde(default)]
    pub public_key_fingerprint: Option<String>,
    #[serde(default)]
    pub issued_credential_pem: Option<String>,
    #[serde(default)]
    pub credential_fingerprint: Option<String>,
    pub created_at_unix: u64,
    #[serde(default)]
    pub revocation_reason: Option<String>,
    #[serde(default)]
    pub revoked_by_actor: Option<String>,
    #[serde(default)]
    pub revoked_by_source_node: Option<String>,
    pub revoked_at_unix: Option<u64>,
}

#[derive(Debug)]
pub enum StoreReadError {
    NotFound,
    Corrupt(String),
    Internal(anyhow::Error),
}

impl std::fmt::Display for StoreReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "object not found"),
            Self::Corrupt(msg) => write!(f, "corrupt data: {msg}"),
            Self::Internal(err) => write!(f, "internal store error: {err}"),
        }
    }
}

impl std::error::Error for StoreReadError {}

#[derive(Debug, Clone)]
pub struct PutOptions {
    pub parent_version_ids: Vec<String>,
    pub state: VersionConsistencyState,
    pub inherit_preferred_parent: bool,
    pub create_snapshot: bool,
    pub explicit_version_id: Option<String>,
}

impl Default for PutOptions {
    fn default() -> Self {
        Self {
            parent_version_ids: Vec::new(),
            state: VersionConsistencyState::Confirmed,
            inherit_preferred_parent: true,
            create_snapshot: true,
            explicit_version_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileVersionEntry {
    pub key: String,
    pub version_id: String,
    pub manifest_hash: String,
    pub parent_version_ids: Vec<String>,
    pub state: VersionConsistencyState,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationChunkInfo {
    pub hash: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadChunkRef {
    pub hash: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ObjectReadDescriptor {
    pub manifest_hash: String,
    pub total_size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ObjectStreamChunkPlan {
    pub hash: String,
    pub path: PathBuf,
    pub start: usize,
    pub len: usize,
}

#[derive(Debug, Clone)]
pub struct ObjectStreamPlan {
    pub chunks: Vec<ObjectStreamChunkPlan>,
}

impl ObjectStreamPlan {
    pub fn content_length(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.len).sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationManifestPayload {
    pub key: String,
    pub total_size_bytes: usize,
    pub chunks: Vec<ReplicationChunkInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationExportBundle {
    pub key: String,
    pub version_id: Option<String>,
    pub parent_version_ids: Vec<String>,
    pub state: VersionConsistencyState,
    pub manifest_hash: String,
    pub manifest_bytes: Vec<u8>,
    pub manifest: ReplicationManifestPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataVersionRecord {
    pub version_id: String,
    pub manifest_hash: String,
    #[serde(default)]
    pub logical_path: Option<String>,
    pub parent_version_ids: Vec<String>,
    pub state: VersionConsistencyState,
    pub created_at_unix: u64,
    pub copied_from_object_id: Option<String>,
    pub copied_from_version_id: Option<String>,
    pub copied_from_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataManifestRecord {
    pub manifest_hash: String,
    pub manifest_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataExportBundle {
    pub key: String,
    pub object_id: Option<String>,
    pub current_manifest_hash: Option<String>,
    pub versions: Vec<MetadataVersionRecord>,
    pub manifests: Vec<MetadataManifestRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairAttemptRecord {
    pub attempts: u32,
    pub last_failure_unix: u64,
}

#[derive(Debug, Clone)]
pub struct PutResult {
    pub snapshot_id: String,
    pub version_id: String,
    pub manifest_hash: String,
    pub state: VersionConsistencyState,
    pub new_chunks: usize,
    pub dedup_reused_chunks: usize,
    pub created_new_version: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MediaCacheStatus {
    Ready,
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

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataBackendKind {
    Sqlite,
    #[cfg(feature = "turso-metadata")]
    Turso,
}

pub struct PersistentStore {
    root_dir: PathBuf,
    chunks_dir: PathBuf,
    manifests_dir: PathBuf,
    metadata_db_path: PathBuf,
    media_thumbnails_dir: PathBuf,
    current_state: CurrentState,
    metadata_store: Arc<dyn MetadataStore>,
    storage_stats_lock: Arc<AsyncMutex<()>>,
    chunk_ingestor: ChunkIngestor,
}

#[derive(Clone)]
pub(crate) struct ChunkIngestor {
    chunks_dir: PathBuf,
    metadata_store: Arc<dyn MetadataStore>,
    storage_stats_lock: Arc<AsyncMutex<()>>,
}

#[derive(Clone)]
pub(crate) struct MediaCacheWorker {
    manifests_dir: PathBuf,
    chunks_dir: PathBuf,
    media_thumbnails_dir: PathBuf,
    metadata_store: Arc<dyn MetadataStore>,
}

#[derive(Clone)]
pub(crate) struct StorageStatsCollector {
    root_dir: PathBuf,
    chunks_dir: PathBuf,
    manifests_dir: PathBuf,
    metadata_db_path: PathBuf,
    media_thumbnails_dir: PathBuf,
    metadata_store: Arc<dyn MetadataStore>,
    storage_stats_lock: Arc<AsyncMutex<()>>,
}

#[derive(Clone)]
pub(crate) struct StoreIndexInspector {
    current_state: CurrentState,
    manifests_dir: PathBuf,
    metadata_store: Arc<dyn MetadataStore>,
}

#[derive(Clone)]
pub(crate) struct ClusterReplicasPersister {
    metadata_store: Arc<dyn MetadataStore>,
}

#[derive(Clone)]
pub(crate) struct ReplicationSubjectInspector {
    current_state: CurrentState,
    manifests_dir: PathBuf,
    chunks_dir: PathBuf,
    metadata_store: Arc<dyn MetadataStore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReconcileMarker {
    source_node_id: String,
    key: String,
    source_version_id: String,
    local_version_id: Option<String>,
    imported_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArchivedTombstoneIndexRecord {
    object_id: String,
    preferred_tombstone_version_id: String,
    preferred_tombstone_created_at_unix: u64,
    archived_at_unix: u64,
    index: FileVersionIndex,
}

#[async_trait]
trait MetadataStore: Send + Sync {
    async fn load_current_state(&self) -> Result<CurrentState>;
    async fn load_repair_attempts(&self) -> Result<HashMap<String, RepairAttemptRecord>>;
    async fn persist_repair_attempts(
        &self,
        attempts: &HashMap<String, RepairAttemptRecord>,
    ) -> Result<()>;
    async fn load_cluster_replicas(&self) -> Result<HashMap<String, Vec<NodeId>>>;
    async fn persist_cluster_replicas(&self, replicas: &HashMap<String, Vec<NodeId>>)
    -> Result<()>;
    async fn load_client_credential_state(&self) -> Result<ClientCredentialState>;
    async fn persist_client_credential_state(&self, state: &ClientCredentialState) -> Result<()>;
    async fn load_snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>>;
    async fn load_cached_media_metadata(
        &self,
        content_fingerprint: &str,
    ) -> Result<Option<CachedMediaMetadata>>;
    async fn persist_media_cache_record(&self, metadata: &CachedMediaMetadata) -> Result<()>;
    async fn delete_media_cache_record(&self, content_fingerprint: &str) -> Result<()>;
    async fn list_snapshot_infos(&self) -> Result<Vec<SnapshotInfo>>;
    async fn append_admin_audit_event(&self, event: &AdminAuditEvent) -> Result<()>;
    async fn load_version_index_by_object_id(
        &self,
        object_id: &str,
    ) -> Result<Option<FileVersionIndex>>;
    async fn persist_version_index_by_object_id(
        &self,
        object_id: &str,
        index: &FileVersionIndex,
    ) -> Result<()>;
    async fn persist_current_state(&self, current_state: &CurrentState) -> Result<()>;
    async fn load_all_version_indexes(&self) -> Result<Vec<FileVersionIndex>>;
    async fn persist_snapshot_manifest(&self, manifest: &SnapshotManifest) -> Result<()>;
    async fn load_all_snapshots(&self) -> Result<Vec<SnapshotManifest>>;
    async fn load_storage_stats_state(&self) -> Result<Option<StorageStatsState>>;
    async fn persist_storage_stats_state(&self, state: &StorageStatsState) -> Result<()>;
    async fn load_cached_chunk_record(&self, hash: &str) -> Result<Option<CachedChunkRecord>>;
    async fn persist_cached_chunk_record(&self, record: &CachedChunkRecord) -> Result<()>;
    async fn delete_cached_chunk_record(&self, hash: &str) -> Result<()>;
    async fn list_cached_chunk_records(&self) -> Result<Vec<CachedChunkRecord>>;
    async fn mark_manifest_locally_owned(
        &self,
        manifest_hash: &str,
        owned_at_unix: u64,
    ) -> Result<()>;
    async fn delete_locally_owned_manifest(&self, manifest_hash: &str) -> Result<()>;
    async fn list_locally_owned_manifests(&self) -> Result<Vec<String>>;
    async fn load_current_storage_stats(&self) -> Result<Option<StorageStatsSample>>;
    async fn list_storage_stats_history(&self, limit: usize) -> Result<Vec<StorageStatsSample>>;
    async fn persist_storage_stats_sample(&self, sample: &StorageStatsSample) -> Result<()>;
    async fn prune_storage_stats_history_before(&self, collected_before_unix: u64) -> Result<()>;
    async fn has_version_index(&self, object_id: &str) -> Result<bool>;
    async fn delete_version_index_by_object_id(&self, object_id: &str) -> Result<()>;
    async fn list_media_cache_fingerprints(&self) -> Result<Vec<String>>;
    async fn has_reconcile_marker(
        &self,
        source_node_id: &str,
        key: &str,
        source_version_id: &str,
    ) -> Result<bool>;
    async fn mark_reconciled(&self, marker: &ReconcileMarker) -> Result<()>;
}

impl ChunkIngestor {
    fn new(
        chunks_dir: PathBuf,
        metadata_store: Arc<dyn MetadataStore>,
        storage_stats_lock: Arc<AsyncMutex<()>>,
    ) -> Self {
        Self {
            chunks_dir,
            metadata_store,
            storage_stats_lock,
        }
    }

    pub(crate) async fn ingest_chunk(&self, hash: &str, payload: &[u8]) -> Result<bool> {
        let actual_hash = hash_hex(payload);
        if actual_hash != hash {
            bail!("chunk hash mismatch: expected={hash} actual={actual_hash}");
        }

        let chunk_path = chunk_path_for_hash(&self.chunks_dir, hash);
        if fs::try_exists(&chunk_path).await? {
            return Ok(false);
        }

        if let Some(parent) = chunk_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        write_atomic(&chunk_path, payload).await?;
        self.note_chunk_store_delta(payload.len() as i64).await?;
        Ok(true)
    }

    pub(crate) async fn ingest_chunk_auto(&self, payload: &[u8]) -> Result<(String, bool)> {
        let hash = hash_hex(payload);
        let stored = self.ingest_chunk(&hash, payload).await?;
        Ok((hash, stored))
    }

    async fn reconcile_chunk_store_bytes_state(&self) -> Result<StorageStatsState> {
        let state = StorageStatsState {
            chunk_store_bytes: directory_size_bytes(&self.chunks_dir).await?,
            last_reconciled_unix: unix_ts(),
        };
        self.metadata_store
            .persist_storage_stats_state(&state)
            .await?;
        Ok(state)
    }

    async fn note_chunk_store_delta(&self, delta_bytes: i64) -> Result<u64> {
        let _guard = self.storage_stats_lock.lock().await;

        let Some(mut state) = self.metadata_store.load_storage_stats_state().await? else {
            return Ok(self
                .reconcile_chunk_store_bytes_state()
                .await?
                .chunk_store_bytes);
        };

        if delta_bytes >= 0 {
            state.chunk_store_bytes = state.chunk_store_bytes.saturating_add(delta_bytes as u64);
        } else {
            state.chunk_store_bytes = state
                .chunk_store_bytes
                .saturating_sub(delta_bytes.unsigned_abs());
        }

        self.metadata_store
            .persist_storage_stats_state(&state)
            .await?;
        Ok(state.chunk_store_bytes)
    }
}

impl MediaCacheWorker {
    fn new(
        manifests_dir: PathBuf,
        chunks_dir: PathBuf,
        media_thumbnails_dir: PathBuf,
        metadata_store: Arc<dyn MetadataStore>,
    ) -> Self {
        Self {
            manifests_dir,
            chunks_dir,
            media_thumbnails_dir,
            metadata_store,
        }
    }

    pub(crate) async fn ensure_media_cache(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        let ensure_started_at = Instant::now();
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
            return Ok(None);
        };
        let content_fingerprint = content_fingerprint_from_manifest(&manifest);
        if let Some(existing) = current_media_cache_metadata(
            self.load_cached_media_metadata(&content_fingerprint)
                .await?,
        ) {
            let total_ms = ensure_started_at.elapsed().as_millis();
            if total_ms >= SLOW_MEDIA_CACHE_GENERATION_LOG_THRESHOLD_MS {
                warn!(
                    manifest_hash,
                    content_fingerprint = %content_fingerprint,
                    total_ms,
                    cache_hit = true,
                    status = ?existing.status,
                    has_thumbnail = existing.thumbnail.is_some(),
                    "slow media cache ensure"
                );
            }
            return Ok(Some(existing));
        }

        info!(
            manifest_hash,
            content_fingerprint = %content_fingerprint,
            source_size_bytes = manifest.total_size_bytes,
            "media cache miss; generating thumbnail"
        );

        let read_started_at = Instant::now();
        let payload = self.read_object_by_manifest_hash(manifest_hash).await?;
        let read_object_ms = read_started_at.elapsed().as_millis();
        let build_started_at = Instant::now();
        let metadata = self.build_media_cache_record(
            manifest_hash,
            &content_fingerprint,
            manifest.total_size_bytes,
            &payload,
        );
        let build_record_ms = build_started_at.elapsed().as_millis();
        let persist_started_at = Instant::now();
        self.persist_media_cache_record(&metadata).await?;
        let persist_ms = persist_started_at.elapsed().as_millis();
        let total_ms = ensure_started_at.elapsed().as_millis();
        info!(
            manifest_hash,
            content_fingerprint = %content_fingerprint,
            total_ms,
            read_object_ms,
            build_record_ms,
            persist_ms,
            status = ?metadata.status,
            has_thumbnail = metadata.thumbnail.is_some(),
            "media cache generation finished"
        );
        if total_ms >= SLOW_MEDIA_CACHE_GENERATION_LOG_THRESHOLD_MS {
            warn!(
                manifest_hash,
                content_fingerprint = %content_fingerprint,
                total_ms,
                read_object_ms,
                build_record_ms,
                persist_ms,
                status = ?metadata.status,
                has_thumbnail = metadata.thumbnail.is_some(),
                "slow media cache generation"
            );
        }
        Ok(Some(metadata))
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

    async fn read_object_by_manifest_hash(
        &self,
        manifest_hash: &str,
    ) -> std::result::Result<Bytes, StoreReadError> {
        let Some(manifest) = self
            .load_manifest_by_hash(manifest_hash)
            .await
            .map_err(StoreReadError::Internal)?
        else {
            return Err(StoreReadError::Corrupt(format!(
                "manifest missing for hash={manifest_hash}"
            )));
        };

        let mut assembled = BytesMut::with_capacity(manifest.total_size_bytes);

        for chunk in manifest.chunks {
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
            if !fs::try_exists(&chunk_path)
                .await
                .map_err(|err| StoreReadError::Internal(err.into()))?
            {
                return Err(StoreReadError::Corrupt(format!(
                    "missing chunk hash={}",
                    chunk.hash
                )));
            }

            let payload = fs::read(&chunk_path)
                .await
                .map_err(|err| StoreReadError::Internal(err.into()))?;

            if payload.len() != chunk.size_bytes {
                return Err(StoreReadError::Corrupt(format!(
                    "size mismatch for chunk hash={} expected={} actual={}",
                    chunk.hash,
                    chunk.size_bytes,
                    payload.len()
                )));
            }

            let actual_hash = hash_hex(&payload);
            if actual_hash != chunk.hash {
                return Err(StoreReadError::Corrupt(format!(
                    "hash mismatch for chunk expected={} actual={}",
                    chunk.hash, actual_hash
                )));
            }

            assembled.extend_from_slice(&payload);
        }

        if assembled.len() != manifest.total_size_bytes {
            return Err(StoreReadError::Corrupt(format!(
                "assembled payload size mismatch key={} expected={} actual={}",
                manifest.key,
                manifest.total_size_bytes,
                assembled.len()
            )));
        }

        Ok(assembled.freeze())
    }

    async fn load_cached_media_metadata(
        &self,
        content_fingerprint: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        self.metadata_store
            .load_cached_media_metadata(content_fingerprint)
            .await
    }

    fn build_media_cache_record(
        &self,
        manifest_hash: &str,
        content_fingerprint: &str,
        source_size_bytes: usize,
        payload: &[u8],
    ) -> CachedMediaMetadata {
        let generated_at_unix = unix_ts();
        match derive_image_media_cache(
            manifest_hash,
            content_fingerprint,
            source_size_bytes,
            payload,
        ) {
            Ok(derived) => derived,
            Err(err) => CachedMediaMetadata {
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
                error: Some(err.to_string()),
            },
        }
    }

    async fn persist_media_cache_record(&self, metadata: &CachedMediaMetadata) -> Result<()> {
        if let Some(thumbnail) = &metadata.thumbnail {
            let thumbnail_path =
                self.media_thumbnail_path(&metadata.content_fingerprint, &thumbnail.profile);
            let payload = self
                .render_thumbnail_payload(
                    &metadata.source_manifest_hash,
                    GRID_THUMBNAIL_MAX_DIMENSION,
                )
                .await?;
            write_atomic(&thumbnail_path, &payload).await?;
        }
        self.metadata_store
            .persist_media_cache_record(metadata)
            .await
    }

    async fn render_thumbnail_payload(
        &self,
        manifest_hash: &str,
        max_dimension: u32,
    ) -> Result<Vec<u8>> {
        let payload = self
            .read_object_by_manifest_hash(manifest_hash)
            .await
            .map_err(|err| anyhow::anyhow!("failed to read object for thumbnail render: {err}"))?;
        render_thumbnail_from_payload(&payload, extract_exif_orientation(&payload), max_dimension)
            .map(|rendered| rendered.payload)
    }

    fn media_thumbnail_path(&self, content_fingerprint: &str, profile: &str) -> PathBuf {
        self.media_thumbnails_dir
            .join(content_fingerprint)
            .join(format!("{profile}.jpg"))
    }
}

impl StorageStatsCollector {
    fn new(
        root_dir: PathBuf,
        chunks_dir: PathBuf,
        manifests_dir: PathBuf,
        metadata_db_path: PathBuf,
        media_thumbnails_dir: PathBuf,
        metadata_store: Arc<dyn MetadataStore>,
        storage_stats_lock: Arc<AsyncMutex<()>>,
    ) -> Self {
        Self {
            root_dir,
            chunks_dir,
            manifests_dir,
            metadata_db_path,
            media_thumbnails_dir,
            metadata_store,
            storage_stats_lock,
        }
    }

    async fn load_storage_stats_state(&self) -> Result<Option<StorageStatsState>> {
        self.metadata_store.load_storage_stats_state().await
    }

    async fn persist_storage_stats_state(&self, state: &StorageStatsState) -> Result<()> {
        self.metadata_store.persist_storage_stats_state(state).await
    }

    async fn load_snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
        self.metadata_store
            .load_snapshot_manifest(snapshot_id)
            .await
    }

    async fn snapshot_object_state(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<SnapshotObjectState>> {
        Ok(self
            .load_snapshot_manifest(snapshot_id)
            .await?
            .map(|manifest| SnapshotObjectState {
                created_at_unix: manifest.created_at_unix,
                objects: manifest.objects,
                object_ids: manifest.object_ids,
            }))
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

    async fn reconcile_chunk_store_bytes_state(&self) -> Result<StorageStatsState> {
        let _guard = self.storage_stats_lock.lock().await;
        let state = StorageStatsState {
            chunk_store_bytes: directory_size_bytes(&self.chunks_dir).await?,
            last_reconciled_unix: unix_ts(),
        };
        self.persist_storage_stats_state(&state).await?;
        Ok(state)
    }

    pub(crate) async fn current_chunk_store_bytes(
        &self,
        reconcile_max_age_secs: Option<u64>,
    ) -> Result<u64> {
        let now = unix_ts();
        let cached_bytes = {
            let _guard = self.storage_stats_lock.lock().await;
            self.load_storage_stats_state().await?.and_then(|state| {
                let should_reconcile = reconcile_max_age_secs
                    .map(|max_age| now.saturating_sub(state.last_reconciled_unix) > max_age)
                    .unwrap_or(false);
                (!should_reconcile).then_some(state.chunk_store_bytes)
            })
        };

        if let Some(bytes) = cached_bytes {
            return Ok(bytes);
        }

        Ok(self
            .reconcile_chunk_store_bytes_state()
            .await?
            .chunk_store_bytes)
    }

    pub(crate) async fn collect_storage_stats_sample(&self) -> Result<StorageStatsSample> {
        let metadata_db_bytes = file_size_bytes(&self.metadata_db_path).await?;
        let chunk_store_bytes = self.current_chunk_store_bytes(None).await?;
        let manifest_store_bytes = directory_size_bytes(&self.manifests_dir).await?;
        let media_cache_root = self
            .media_thumbnails_dir
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| self.root_dir.join("state").join("media_cache"));
        let media_cache_bytes = directory_size_bytes(&media_cache_root).await?;

        let latest_snapshot = self
            .metadata_store
            .list_snapshot_infos()
            .await?
            .into_iter()
            .next();
        let mut latest_snapshot_id = None;
        let mut latest_snapshot_created_at_unix = None;
        let mut latest_snapshot_object_count = 0usize;
        let mut latest_snapshot_logical_bytes = 0u64;
        let mut latest_snapshot_unique_chunk_bytes = 0u64;

        if let Some(snapshot) = latest_snapshot {
            latest_snapshot_id = Some(snapshot.id.clone());
            latest_snapshot_created_at_unix = Some(snapshot.created_at_unix);
            latest_snapshot_object_count = snapshot.object_count;

            if let Some(snapshot_state) = self.snapshot_object_state(&snapshot.id).await? {
                let mut seen_chunk_hashes = HashSet::new();
                let mut manifest_cache = HashMap::<String, ObjectManifest>::new();

                for manifest_hash in snapshot_state.objects.values() {
                    let manifest = if let Some(existing) = manifest_cache.get(manifest_hash) {
                        existing.clone()
                    } else {
                        let Some(loaded) = self.load_manifest_by_hash(manifest_hash).await? else {
                            continue;
                        };
                        manifest_cache.insert(manifest_hash.clone(), loaded.clone());
                        loaded
                    };

                    latest_snapshot_logical_bytes = latest_snapshot_logical_bytes
                        .saturating_add(manifest.total_size_bytes as u64);
                    for chunk in manifest.chunks {
                        if seen_chunk_hashes.insert(chunk.hash) {
                            latest_snapshot_unique_chunk_bytes = latest_snapshot_unique_chunk_bytes
                                .saturating_add(chunk.size_bytes as u64);
                        }
                    }
                }
            }
        }

        Ok(StorageStatsSample {
            collected_at_unix: unix_ts(),
            latest_snapshot_id,
            latest_snapshot_created_at_unix,
            latest_snapshot_object_count,
            chunk_store_bytes,
            manifest_store_bytes,
            metadata_db_bytes,
            media_cache_bytes,
            latest_snapshot_logical_bytes,
            latest_snapshot_unique_chunk_bytes,
        })
    }

    pub(crate) async fn persist_storage_stats_sample(
        &self,
        sample: &StorageStatsSample,
    ) -> Result<()> {
        self.metadata_store
            .persist_storage_stats_sample(sample)
            .await
    }

    pub(crate) async fn prune_storage_stats_history_before(
        &self,
        collected_before_unix: u64,
    ) -> Result<()> {
        self.metadata_store
            .prune_storage_stats_history_before(collected_before_unix)
            .await
    }
}

impl StoreIndexInspector {
    fn new(
        current_state: CurrentState,
        manifests_dir: PathBuf,
        metadata_store: Arc<dyn MetadataStore>,
    ) -> Self {
        Self {
            current_state,
            manifests_dir,
            metadata_store,
        }
    }

    pub(crate) fn current_object_hashes(&self) -> HashMap<String, String> {
        self.current_state.objects.clone()
    }

    pub(crate) fn current_object_ids(&self) -> HashMap<String, String> {
        self.current_state.object_ids.clone()
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

    async fn load_version_index_by_object_id(
        &self,
        object_id: &str,
    ) -> Result<Option<FileVersionIndex>> {
        self.metadata_store
            .load_version_index_by_object_id(object_id)
            .await
    }

    async fn load_snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
        self.metadata_store
            .load_snapshot_manifest(snapshot_id)
            .await
    }

    pub(crate) async fn snapshot_object_state(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<SnapshotObjectState>> {
        Ok(self
            .load_snapshot_manifest(snapshot_id)
            .await?
            .map(|manifest| SnapshotObjectState {
                created_at_unix: manifest.created_at_unix,
                objects: manifest.objects,
                object_ids: manifest.object_ids,
            }))
    }

    pub(crate) async fn object_sizes_by_key(
        &self,
        object_hashes: &HashMap<String, String>,
    ) -> Result<HashMap<String, u64>> {
        let mut sizes = HashMap::with_capacity(object_hashes.len());
        for (key, manifest_hash) in object_hashes {
            if let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? {
                sizes.insert(key.clone(), manifest.total_size_bytes as u64);
            }
        }
        Ok(sizes)
    }

    pub(crate) async fn object_modified_at_by_key(
        &self,
        object_hashes: &HashMap<String, String>,
        object_ids: &HashMap<String, String>,
        max_created_at_unix: Option<u64>,
    ) -> Result<HashMap<String, u64>> {
        let mut modified = HashMap::with_capacity(object_hashes.len());
        for (key, manifest_hash) in object_hashes {
            let Some(object_id) = object_ids.get(key) else {
                continue;
            };
            let Some(index) = self.load_version_index_by_object_id(object_id).await? else {
                continue;
            };

            let matching_created_at = index
                .versions
                .values()
                .filter(|record| record.manifest_hash == *manifest_hash)
                .filter(|record| {
                    max_created_at_unix
                        .map(|limit| record.created_at_unix <= limit)
                        .unwrap_or(true)
                })
                .map(|record| record.created_at_unix)
                .max()
                .or_else(|| {
                    index
                        .versions
                        .values()
                        .filter(|record| record.manifest_hash == *manifest_hash)
                        .map(|record| record.created_at_unix)
                        .max()
                });

            if let Some(created_at_unix) = matching_created_at {
                modified.insert(key.clone(), created_at_unix);
            }
        }
        Ok(modified)
    }

    pub(crate) async fn lookup_media_cache(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<MediaCacheLookup>> {
        let lookup_started_at = Instant::now();
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
            return Ok(None);
        };
        let content_fingerprint = content_fingerprint_from_manifest(&manifest);
        let metadata = current_media_cache_metadata(
            self.metadata_store
                .load_cached_media_metadata(&content_fingerprint)
                .await?,
        );
        let total_ms = lookup_started_at.elapsed().as_millis();
        if total_ms >= SLOW_MEDIA_CACHE_LOOKUP_LOG_THRESHOLD_MS {
            warn!(
                manifest_hash,
                content_fingerprint = %content_fingerprint,
                total_ms,
                metadata_present = metadata.is_some(),
                "slow media cache lookup"
            );
        }

        Ok(Some(MediaCacheLookup {
            content_fingerprint,
            metadata,
        }))
    }
}

impl ClusterReplicasPersister {
    fn new(metadata_store: Arc<dyn MetadataStore>) -> Self {
        Self { metadata_store }
    }

    pub(crate) async fn persist_cluster_replicas(
        &self,
        replicas: &HashMap<String, Vec<NodeId>>,
    ) -> Result<()> {
        self.metadata_store.persist_cluster_replicas(replicas).await
    }
}

impl ReplicationSubjectInspector {
    fn new(
        current_state: CurrentState,
        manifests_dir: PathBuf,
        chunks_dir: PathBuf,
        metadata_store: Arc<dyn MetadataStore>,
    ) -> Self {
        Self {
            current_state,
            manifests_dir,
            chunks_dir,
            metadata_store,
        }
    }

    pub(crate) async fn list_replication_subjects(&self) -> Result<Vec<String>> {
        let mut subjects: HashSet<String> = HashSet::new();
        let mut indexed_object_ids = HashSet::new();

        for (key, manifest_hash) in &self.current_state.objects {
            if self.manifest_is_fully_local(manifest_hash).await? {
                subjects.insert(key.clone());
            }
        }

        for (path, object_id) in &self.current_state.object_ids {
            if let Some(index) = self.load_version_index_by_object_id(object_id).await? {
                indexed_object_ids.insert(object_id.clone());
                for head_version_id in &index.head_version_ids {
                    let Some(record) = index.versions.get(head_version_id) else {
                        continue;
                    };
                    if record.manifest_hash == TOMBSTONE_MANIFEST_HASH
                        || self.manifest_is_fully_local(&record.manifest_hash).await?
                    {
                        subjects.insert(format!("{path}@{head_version_id}"));
                    }
                }
            }
        }

        for index in self.load_all_version_indexes().await? {
            if indexed_object_ids.contains(&index.object_id) {
                continue;
            }

            let Some(key) = self.resolve_key_for_version_index(&index).await? else {
                continue;
            };

            for head_version_id in &index.head_version_ids {
                let Some(record) = index.versions.get(head_version_id) else {
                    continue;
                };
                if record.manifest_hash == TOMBSTONE_MANIFEST_HASH
                    || self.manifest_is_fully_local(&record.manifest_hash).await?
                {
                    subjects.insert(format!("{key}@{head_version_id}"));
                }
            }
        }

        let mut output: Vec<String> = subjects.into_iter().collect();
        output.sort();
        Ok(output)
    }

    pub(crate) fn current_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.current_state.objects.keys().cloned().collect();
        keys.sort();
        keys
    }

    async fn manifest_is_fully_local(&self, manifest_hash: &str) -> Result<bool> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(true);
        }

        let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
            return Ok(false);
        };

        for chunk in &manifest.chunks {
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
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

    async fn load_version_index_by_object_id(
        &self,
        object_id: &str,
    ) -> Result<Option<FileVersionIndex>> {
        self.metadata_store
            .load_version_index_by_object_id(object_id)
            .await
    }

    async fn load_all_version_indexes(&self) -> Result<Vec<FileVersionIndex>> {
        self.metadata_store.load_all_version_indexes().await
    }

    async fn resolve_key_for_version_index(
        &self,
        index: &FileVersionIndex,
    ) -> Result<Option<String>> {
        if let Some(preferred_head) = index
            .preferred_head_version_id
            .as_ref()
            .and_then(|version_id| index.versions.get(version_id))
            .and_then(|record| record.logical_path.clone())
        {
            return Ok(Some(preferred_head));
        }

        if let Some(any_logical_path) = index
            .versions
            .values()
            .find_map(|record| record.logical_path.clone())
        {
            return Ok(Some(any_logical_path));
        }

        for record in index.versions.values() {
            if record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
                continue;
            }

            if let Some(manifest) = self.load_manifest_by_hash(&record.manifest_hash).await? {
                return Ok(Some(manifest.key));
            }
        }

        Ok(None)
    }
}

impl PersistentStore {
    #[allow(dead_code)]
    pub async fn init_with_sqlite_metadata(root_dir: impl Into<PathBuf>) -> Result<Self> {
        Self::init_with_metadata_backend(root_dir, MetadataBackendKind::Sqlite).await
    }

    #[allow(dead_code)]
    #[cfg(feature = "turso-metadata")]
    pub async fn init_with_turso_metadata(root_dir: impl Into<PathBuf>) -> Result<Self> {
        Self::init_with_metadata_backend(root_dir, MetadataBackendKind::Turso).await
    }

    pub async fn init_with_metadata_backend(
        root_dir: impl Into<PathBuf>,
        backend: MetadataBackendKind,
    ) -> Result<Self> {
        let root_dir = root_dir.into();
        let chunks_dir = root_dir.join("chunks");
        let manifests_dir = root_dir.join("manifests");
        let state_dir = root_dir.join("state");
        let media_cache_dir = state_dir.join("media_cache");
        let media_thumbnails_dir = media_cache_dir.join("thumbnails");

        fs::create_dir_all(&chunks_dir).await?;
        fs::create_dir_all(&manifests_dir).await?;
        fs::create_dir_all(&state_dir).await?;
        fs::create_dir_all(&media_thumbnails_dir).await?;

        let (metadata_db_path, metadata_store): (PathBuf, Arc<dyn MetadataStore>) = match backend {
            MetadataBackendKind::Sqlite => (
                state_dir.join("metadata.sqlite"),
                Arc::new(SqliteMetadataStore::open(
                    &state_dir.join("metadata.sqlite"),
                )?),
            ),
            #[cfg(feature = "turso-metadata")]
            MetadataBackendKind::Turso => {
                let turso_path = state_dir.join("metadata.turso.db");
                (
                    turso_path.clone(),
                    Arc::new(TursoMetadataStore::open(&turso_path).await?),
                )
            }
        };
        let current_state = metadata_store.load_current_state().await?;
        let storage_stats_lock = Arc::new(AsyncMutex::new(()));
        let chunk_ingestor = ChunkIngestor::new(
            chunks_dir.clone(),
            metadata_store.clone(),
            storage_stats_lock.clone(),
        );

        Ok(Self {
            root_dir,
            chunks_dir,
            manifests_dir,
            metadata_db_path,
            media_thumbnails_dir,
            current_state,
            metadata_store,
            storage_stats_lock,
            chunk_ingestor,
        })
    }

    pub(crate) fn chunk_ingestor(&self) -> ChunkIngestor {
        self.chunk_ingestor.clone()
    }

    pub(crate) fn media_cache_worker(&self) -> MediaCacheWorker {
        MediaCacheWorker::new(
            self.manifests_dir.clone(),
            self.chunks_dir.clone(),
            self.media_thumbnails_dir.clone(),
            self.metadata_store.clone(),
        )
    }

    pub(crate) fn store_index_inspector(&self) -> StoreIndexInspector {
        StoreIndexInspector::new(
            self.current_state.clone(),
            self.manifests_dir.clone(),
            self.metadata_store.clone(),
        )
    }

    pub(crate) fn storage_stats_collector(&self) -> StorageStatsCollector {
        StorageStatsCollector::new(
            self.root_dir.clone(),
            self.chunks_dir.clone(),
            self.manifests_dir.clone(),
            self.metadata_db_path.clone(),
            self.media_thumbnails_dir.clone(),
            self.metadata_store.clone(),
            self.storage_stats_lock.clone(),
        )
    }

    pub(crate) fn cluster_replicas_persister(&self) -> ClusterReplicasPersister {
        ClusterReplicasPersister::new(self.metadata_store.clone())
    }

    pub(crate) fn replication_subject_inspector(&self) -> ReplicationSubjectInspector {
        ReplicationSubjectInspector::new(
            self.current_state.clone(),
            self.manifests_dir.clone(),
            self.chunks_dir.clone(),
            self.metadata_store.clone(),
        )
    }

    pub async fn load_repair_attempts(&self) -> Result<HashMap<String, RepairAttemptRecord>> {
        self.metadata_store.load_repair_attempts().await
    }

    pub async fn persist_repair_attempts(
        &self,
        attempts: &HashMap<String, RepairAttemptRecord>,
    ) -> Result<()> {
        self.metadata_store.persist_repair_attempts(attempts).await
    }

    pub async fn load_cluster_replicas(&self) -> Result<HashMap<String, Vec<NodeId>>> {
        self.metadata_store.load_cluster_replicas().await
    }

    #[cfg(test)]
    pub async fn persist_cluster_replicas(
        &self,
        replicas: &HashMap<String, Vec<NodeId>>,
    ) -> Result<()> {
        self.metadata_store.persist_cluster_replicas(replicas).await
    }

    pub async fn load_client_credential_state(&self) -> Result<ClientCredentialState> {
        self.metadata_store.load_client_credential_state().await
    }

    pub async fn persist_client_credential_state(
        &self,
        state: &ClientCredentialState,
    ) -> Result<()> {
        self.metadata_store
            .persist_client_credential_state(state)
            .await
    }

    #[cfg(test)]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    #[cfg(test)]
    pub fn object_count(&self) -> usize {
        self.current_state.objects.len()
    }

    pub fn current_keys(&self) -> Vec<String> {
        self.current_state.objects.keys().cloned().collect()
    }

    #[cfg(test)]
    pub async fn list_cached_chunk_records_for_test(&self) -> Result<Vec<CachedChunkRecord>> {
        self.metadata_store.list_cached_chunk_records().await
    }

    #[cfg(test)]
    pub async fn list_locally_owned_manifests_for_test(&self) -> Result<Vec<String>> {
        self.metadata_store.list_locally_owned_manifests().await
    }

    async fn load_snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
        self.metadata_store
            .load_snapshot_manifest(snapshot_id)
            .await
    }

    pub async fn resolve_manifest_hash_for_key(
        &self,
        key: &str,
        snapshot_id: Option<&str>,
        version_id: Option<&str>,
        read_mode: ObjectReadMode,
    ) -> std::result::Result<String, StoreReadError> {
        let manifest_hash = if let Some(version_id) = version_id {
            let Some(object_id) = self.object_id_for_key(key) else {
                return Err(StoreReadError::NotFound);
            };
            let index = self
                .load_version_index_by_object_id(&object_id)
                .await
                .map_err(StoreReadError::Internal)?;
            let Some(index) = index else {
                return Err(StoreReadError::NotFound);
            };

            index
                .versions
                .get(version_id)
                .map(|record| record.manifest_hash.clone())
        } else if let Some(snapshot_id) = snapshot_id {
            let snapshot = self
                .read_snapshot(snapshot_id)
                .await
                .map_err(StoreReadError::Internal)?;

            match snapshot {
                Some(snapshot) => snapshot.objects.get(key).cloned(),
                None => None,
            }
        } else {
            match self.object_id_for_key(key) {
                Some(object_id) => {
                    let index = self
                        .load_version_index_by_object_id(&object_id)
                        .await
                        .map_err(StoreReadError::Internal)?;
                    match index {
                        Some(index) => manifest_hash_for_read_mode(&index, read_mode),
                        None => self.current_state.objects.get(key).cloned(),
                    }
                }
                None => self.current_state.objects.get(key).cloned(),
            }
        }
        .ok_or(StoreReadError::NotFound)?;

        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Err(StoreReadError::NotFound);
        }

        Ok(manifest_hash)
    }

    #[cfg(test)]
    pub async fn lookup_media_cache(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<MediaCacheLookup>> {
        self.store_index_inspector()
            .lookup_media_cache(manifest_hash)
            .await
    }

    #[cfg(test)]
    pub async fn ensure_media_cache(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
            return Ok(None);
        };
        let content_fingerprint = content_fingerprint_from_manifest(&manifest);
        if let Some(existing) = current_media_cache_metadata(
            self.load_cached_media_metadata(&content_fingerprint)
                .await?,
        ) {
            return Ok(Some(existing));
        }

        let payload = self.read_object_by_manifest_hash(manifest_hash).await?;
        let metadata = self.build_media_cache_record(
            manifest_hash,
            &content_fingerprint,
            manifest.total_size_bytes,
            &payload,
        );
        self.persist_media_cache_record(&metadata).await?;
        Ok(Some(metadata))
    }

    pub async fn list_metadata_subjects(&self) -> Result<Vec<String>> {
        let mut subjects: HashSet<String> = self.current_state.objects.keys().cloned().collect();
        let mut indexed_object_ids = HashSet::new();
        for (path, object_id) in &self.current_state.object_ids {
            if let Some(index) = self.load_version_index_by_object_id(object_id).await? {
                indexed_object_ids.insert(object_id.clone());
                for head_version_id in &index.head_version_ids {
                    subjects.insert(format!("{path}@{head_version_id}"));
                }
            }
        }

        for index in self.load_all_version_indexes().await? {
            if indexed_object_ids.contains(&index.object_id) {
                continue;
            }

            let Some(key) = self.resolve_key_for_version_index(&index).await? else {
                continue;
            };

            for head_version_id in &index.head_version_ids {
                if index
                    .versions
                    .get(head_version_id)
                    .map(|record| record.manifest_hash == TOMBSTONE_MANIFEST_HASH)
                    .unwrap_or(false)
                {
                    subjects.insert(format!("{key}@{head_version_id}"));
                }
            }
        }

        let mut output: Vec<String> = subjects.into_iter().collect();
        output.sort();
        Ok(output)
    }

    #[cfg(test)]
    pub async fn list_replication_subjects(&self) -> Result<Vec<String>> {
        let mut subjects: HashSet<String> = HashSet::new();
        let mut indexed_object_ids = HashSet::new();

        for (key, manifest_hash) in &self.current_state.objects {
            if self.manifest_is_fully_local(manifest_hash).await? {
                subjects.insert(key.clone());
            }
        }

        for (path, object_id) in &self.current_state.object_ids {
            if let Some(index) = self.load_version_index_by_object_id(object_id).await? {
                indexed_object_ids.insert(object_id.clone());
                for head_version_id in &index.head_version_ids {
                    let Some(record) = index.versions.get(head_version_id) else {
                        continue;
                    };
                    if record.manifest_hash == TOMBSTONE_MANIFEST_HASH
                        || self.manifest_is_fully_local(&record.manifest_hash).await?
                    {
                        subjects.insert(format!("{path}@{head_version_id}"));
                    }
                }
            }
        }

        for index in self.load_all_version_indexes().await? {
            if indexed_object_ids.contains(&index.object_id) {
                continue;
            }

            let Some(key) = self.resolve_key_for_version_index(&index).await? else {
                continue;
            };

            for head_version_id in &index.head_version_ids {
                let Some(record) = index.versions.get(head_version_id) else {
                    continue;
                };
                if record.manifest_hash == TOMBSTONE_MANIFEST_HASH
                    || self.manifest_is_fully_local(&record.manifest_hash).await?
                {
                    subjects.insert(format!("{key}@{head_version_id}"));
                }
            }
        }

        let mut output: Vec<String> = subjects.into_iter().collect();
        output.sort();
        Ok(output)
    }

    pub async fn put_object_versioned(
        &mut self,
        key: &str,
        payload: Bytes,
        options: PutOptions,
    ) -> Result<PutResult> {
        let mut chunk_refs = Vec::new();
        let mut new_chunks = 0usize;
        let mut dedup_reused_chunks = 0usize;

        for chunk in payload.chunks(CHUNK_SIZE) {
            let hash = hash_hex(chunk);
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &hash);

            if fs::try_exists(&chunk_path).await? {
                dedup_reused_chunks += 1;
            } else {
                if let Some(parent) = chunk_path.parent() {
                    fs::create_dir_all(parent).await?;
                }
                write_atomic(&chunk_path, chunk).await?;
                new_chunks += 1;
            }

            chunk_refs.push(ChunkRef {
                hash,
                size_bytes: chunk.len(),
            });
        }

        let manifest = ObjectManifest {
            key: key.to_string(),
            total_size_bytes: payload.len(),
            chunks: chunk_refs,
        };

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let manifest_hash = hash_hex(&manifest_bytes);
        let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));

        if !fs::try_exists(&manifest_path).await? {
            write_atomic(&manifest_path, &manifest_bytes).await?;
        }

        self.finalize_put_from_manifest_hash(
            key,
            &manifest_hash,
            options,
            new_chunks,
            dedup_reused_chunks,
        )
        .await
    }

    pub async fn put_object_from_chunks(
        &mut self,
        key: &str,
        total_size_bytes: usize,
        chunk_refs: &[UploadChunkRef],
        options: PutOptions,
    ) -> Result<PutResult> {
        let total_started_at = Instant::now();
        let computed_total_size_bytes = chunk_refs.iter().try_fold(0usize, |acc, chunk_ref| {
            acc.checked_add(chunk_ref.size_bytes).ok_or_else(|| {
                anyhow::anyhow!(
                    "chunk size overflow while validating upload for key={key} hash={}",
                    chunk_ref.hash
                )
            })
        })?;

        if computed_total_size_bytes != total_size_bytes {
            bail!(
                "total_size_bytes mismatch for key={key}: expected={total_size_bytes} computed={computed_total_size_bytes}"
            );
        }

        let chunk_validation_started_at = Instant::now();
        for chunk in chunk_refs {
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
            if !fs::try_exists(&chunk_path).await? {
                bail!(
                    "upload manifest references missing chunk hash={}",
                    chunk.hash
                );
            }

            let metadata = fs::metadata(&chunk_path).await?;
            if metadata.len() != chunk.size_bytes as u64 {
                bail!(
                    "upload chunk size mismatch hash={} expected={} actual={}",
                    chunk.hash,
                    chunk.size_bytes,
                    metadata.len()
                );
            }
        }
        let chunk_validation_ms = chunk_validation_started_at.elapsed().as_millis();

        let manifest_build_started_at = Instant::now();
        let manifest = ObjectManifest {
            key: key.to_string(),
            total_size_bytes,
            chunks: chunk_refs
                .iter()
                .map(|chunk| ChunkRef {
                    hash: chunk.hash.clone(),
                    size_bytes: chunk.size_bytes,
                })
                .collect(),
        };

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let manifest_hash = hash_hex(&manifest_bytes);
        let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));
        let manifest_build_ms = manifest_build_started_at.elapsed().as_millis();

        let manifest_store_started_at = Instant::now();
        if !fs::try_exists(&manifest_path).await? {
            write_atomic(&manifest_path, &manifest_bytes).await?;
        }
        let manifest_store_ms = manifest_store_started_at.elapsed().as_millis();

        let finalize_started_at = Instant::now();
        let result = self
            .finalize_put_from_manifest_hash(key, &manifest_hash, options, 0, 0)
            .await?;
        let finalize_ms = finalize_started_at.elapsed().as_millis();

        info!(
            key = %key,
            total_size_bytes,
            chunk_count = chunk_refs.len(),
            manifest_hash = %manifest_hash,
            chunk_validation_ms,
            manifest_build_ms,
            manifest_store_ms,
            finalize_ms,
            total_ms = total_started_at.elapsed().as_millis(),
            new_chunks = result.new_chunks,
            dedup_reused_chunks = result.dedup_reused_chunks,
            created_new_version = result.created_new_version,
            "stored object from upload chunks"
        );

        Ok(result)
    }

    async fn finalize_put_from_manifest_hash(
        &mut self,
        key: &str,
        manifest_hash: &str,
        options: PutOptions,
        new_chunks: usize,
        dedup_reused_chunks: usize,
    ) -> Result<PutResult> {
        let PutOptions {
            parent_version_ids: requested_parent_version_ids,
            state: requested_state,
            inherit_preferred_parent,
            create_snapshot,
            explicit_version_id,
        } = options;

        let object_id = self
            .object_id_for_key(key)
            .unwrap_or_else(generate_object_id);
        let mut index = self
            .load_version_index_by_object_id(&object_id)
            .await?
            .unwrap_or_else(|| empty_version_index(&object_id));

        let parent_version_ids = if requested_parent_version_ids.is_empty() {
            if inherit_preferred_parent {
                index
                    .preferred_head_version_id
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        } else {
            requested_parent_version_ids.clone()
        };

        for parent in &parent_version_ids {
            if !index.versions.contains_key(parent) {
                bail!("parent version does not exist for key={key}: {parent}");
            }
        }

        self.mark_manifest_locally_owned(manifest_hash).await?;

        let version_id = explicit_version_id
            .clone()
            .unwrap_or_else(|| format!("ver-{}-{}", unix_ts_nanos(), &manifest_hash[..12]));

        if let Some(existing) = index.versions.get(&version_id) {
            if existing.manifest_hash != manifest_hash {
                bail!(
                    "version id collision for key={key} version_id={version_id}: different manifest"
                );
            }

            self.sync_current_state_for_key_from_index(key, &index)?;
            self.persist_current_state().await?;

            let snapshot_id = if create_snapshot {
                self.create_snapshot().await?
            } else {
                format!("snap-skipped-{version_id}")
            };

            return Ok(PutResult {
                snapshot_id,
                version_id,
                manifest_hash: manifest_hash.to_string(),
                state: existing.state.clone(),
                new_chunks,
                dedup_reused_chunks,
                created_new_version: false,
            });
        }

        if explicit_version_id.is_none()
            && let Some(preferred_head_id) = index.preferred_head_version_id.clone()
            && let Some(preferred_head) = index.versions.get(&preferred_head_id)
        {
            let parent_context_matches =
                if requested_parent_version_ids.is_empty() && inherit_preferred_parent {
                    true
                } else {
                    preferred_head.parent_version_ids == parent_version_ids
                };

            if preferred_head.manifest_hash == manifest_hash
                && preferred_head.state == requested_state
                && parent_context_matches
            {
                return Ok(PutResult {
                    snapshot_id: format!("snap-skipped-{preferred_head_id}"),
                    version_id: preferred_head_id,
                    manifest_hash: preferred_head.manifest_hash.clone(),
                    state: preferred_head.state.clone(),
                    new_chunks,
                    dedup_reused_chunks,
                    created_new_version: false,
                });
            }
        }

        let record = FileVersionRecord {
            version_id: version_id.clone(),
            object_id: object_id.clone(),
            manifest_hash: manifest_hash.to_string(),
            logical_path: Some(key.to_string()),
            parent_version_ids: parent_version_ids.clone(),
            state: requested_state.clone(),
            created_at_unix: unix_ts(),
            copied_from_object_id: None,
            copied_from_version_id: None,
            copied_from_path: None,
        };

        index.versions.insert(version_id.clone(), record);

        let mut heads: HashSet<String> = index.head_version_ids.into_iter().collect();
        for parent in &parent_version_ids {
            heads.remove(parent);
        }
        heads.insert(version_id.clone());

        index.head_version_ids = heads.into_iter().collect();
        index.head_version_ids.sort();
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;
        self.sync_current_state_for_key_from_index(key, &index)?;
        self.persist_current_state().await?;

        let snapshot_id = if create_snapshot {
            self.create_snapshot().await?
        } else {
            format!("snap-skipped-{version_id}")
        };

        Ok(PutResult {
            snapshot_id,
            version_id,
            manifest_hash: manifest_hash.to_string(),
            state: requested_state,
            new_chunks,
            dedup_reused_chunks,
            created_new_version: true,
        })
    }

    pub async fn commit_version(&mut self, key: &str, version_id: &str) -> Result<bool> {
        let Some(object_id) = self.object_id_for_key(key) else {
            return Ok(false);
        };

        let mut index = match self.load_version_index_by_object_id(&object_id).await? {
            Some(index) => index,
            None => return Ok(false),
        };

        let Some(version) = index.versions.get_mut(version_id) else {
            return Ok(false);
        };

        if version.state == VersionConsistencyState::Confirmed {
            return Ok(true);
        }

        version.state = VersionConsistencyState::Confirmed;
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;
        self.sync_current_state_for_key_from_index(key, &index)?;
        self.persist_current_state().await?;
        self.create_snapshot().await?;

        Ok(true)
    }

    pub async fn list_versions(&self, key: &str) -> Result<Option<VersionGraphSummary>> {
        let Some(object_id) = self.object_id_for_key(key) else {
            return Ok(None);
        };

        let Some(index) = self.load_version_index_by_object_id(&object_id).await? else {
            return Ok(None);
        };

        let mut versions: Vec<VersionRecordSummary> = index
            .versions
            .values()
            .map(|record| VersionRecordSummary {
                version_id: record.version_id.clone(),
                logical_path: record.logical_path.clone(),
                parent_version_ids: record.parent_version_ids.clone(),
                state: record.state.clone(),
                created_at_unix: record.created_at_unix,
                copied_from_object_id: record.copied_from_object_id.clone(),
                copied_from_version_id: record.copied_from_version_id.clone(),
                copied_from_path: record.copied_from_path.clone(),
            })
            .collect();

        versions.sort_by(|a, b| {
            b.created_at_unix
                .cmp(&a.created_at_unix)
                .then_with(|| b.version_id.cmp(&a.version_id))
        });

        let preferred = choose_preferred_head_with_reason(&index);

        Ok(Some(VersionGraphSummary {
            key: key.to_string(),
            object_id: index.object_id.clone(),
            preferred_head_version_id: preferred.as_ref().map(|(id, _)| id.clone()),
            preferred_head_reason: preferred.map(|(_, reason)| reason),
            head_version_ids: index.head_version_ids,
            versions,
        }))
    }

    pub async fn has_manifest_for_key(&self, key: &str, manifest_hash: &str) -> Result<bool> {
        let Some(object_id) = self.object_id_for_key(key) else {
            return Ok(false);
        };

        let Some(index) = self.load_version_index_by_object_id(&object_id).await? else {
            return Ok(false);
        };

        Ok(index
            .versions
            .values()
            .any(|record| record.manifest_hash == manifest_hash))
    }

    pub async fn export_replication_bundle(
        &self,
        key: &str,
        version_id: Option<&str>,
        read_mode: ObjectReadMode,
    ) -> Result<Option<ReplicationExportBundle>> {
        let object_id = if version_id.is_some() {
            self.resolve_object_id_for_key_history(key).await?
        } else {
            self.object_id_for_key(key)
        };
        let (selected_version_id, parent_version_ids, state, manifest_hash) =
            if let Some(version_id) = version_id {
                let Some(object_id) = object_id.as_ref() else {
                    return Ok(None);
                };

                let Some(index) = self.load_version_index_by_object_id(object_id).await? else {
                    return Ok(None);
                };

                let Some(record) = index.versions.get(version_id) else {
                    return Ok(None);
                };

                (
                    Some(record.version_id.clone()),
                    record.parent_version_ids.clone(),
                    record.state.clone(),
                    record.manifest_hash.clone(),
                )
            } else {
                match object_id {
                    Some(object_id) => {
                        match self.load_version_index_by_object_id(&object_id).await? {
                            Some(index) => {
                                let Some(record) = version_record_for_read_mode(&index, read_mode)
                                else {
                                    return Ok(None);
                                };

                                (
                                    Some(record.version_id.clone()),
                                    record.parent_version_ids.clone(),
                                    record.state.clone(),
                                    record.manifest_hash.clone(),
                                )
                            }
                            None => {
                                let Some(manifest_hash) =
                                    self.current_state.objects.get(key).cloned()
                                else {
                                    return Ok(None);
                                };
                                (
                                    None,
                                    Vec::new(),
                                    VersionConsistencyState::Confirmed,
                                    manifest_hash,
                                )
                            }
                        }
                    }
                    None => {
                        let Some(manifest_hash) = self.current_state.objects.get(key).cloned()
                        else {
                            return Ok(None);
                        };
                        (
                            None,
                            Vec::new(),
                            VersionConsistencyState::Confirmed,
                            manifest_hash,
                        )
                    }
                }
            };

        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(Some(ReplicationExportBundle {
                key: key.to_string(),
                version_id: selected_version_id,
                parent_version_ids,
                state,
                manifest_hash,
                manifest_bytes: Vec::new(),
                manifest: ReplicationManifestPayload {
                    key: key.to_string(),
                    total_size_bytes: 0,
                    chunks: Vec::new(),
                },
            }));
        }

        let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));
        if !fs::try_exists(&manifest_path).await? {
            return Ok(None);
        }

        let manifest_bytes = fs::read(&manifest_path).await?;
        let manifest = serde_json::from_slice::<ObjectManifest>(&manifest_bytes)
            .with_context(|| format!("invalid manifest {}", manifest_path.display()))?;

        Ok(Some(ReplicationExportBundle {
            key: key.to_string(),
            version_id: selected_version_id,
            parent_version_ids,
            state,
            manifest_hash,
            manifest_bytes,
            manifest: ReplicationManifestPayload {
                key: manifest.key,
                total_size_bytes: manifest.total_size_bytes,
                chunks: manifest
                    .chunks
                    .into_iter()
                    .map(|chunk| ReplicationChunkInfo {
                        hash: chunk.hash,
                        size_bytes: chunk.size_bytes,
                    })
                    .collect(),
            },
        }))
    }

    pub async fn export_metadata_bundle(
        &self,
        key: &str,
        version_id: Option<&str>,
        read_mode: ObjectReadMode,
    ) -> Result<Option<MetadataExportBundle>> {
        let object_id = if version_id.is_some() {
            self.resolve_object_id_for_key_history(key).await?
        } else {
            self.object_id_for_key(key)
                .or(self.resolve_object_id_for_key_history(key).await?)
        };

        let current_manifest_hash = self.current_state.objects.get(key).cloned();
        let mut versions = Vec::new();
        let mut manifests = Vec::new();
        let mut seen_manifest_hashes = HashSet::new();

        if let Some(object_id) = object_id.clone()
            && let Some(index) = self.load_version_index_by_object_id(&object_id).await?
        {
            let selected_record = if let Some(version_id) = version_id {
                index.versions.get(version_id)
            } else {
                version_record_for_read_mode(&index, read_mode)
            };

            let Some(record) = selected_record else {
                return Ok(None);
            };

            versions.push(MetadataVersionRecord {
                version_id: record.version_id.clone(),
                manifest_hash: record.manifest_hash.clone(),
                logical_path: record.logical_path.clone(),
                parent_version_ids: record.parent_version_ids.clone(),
                state: record.state.clone(),
                created_at_unix: record.created_at_unix,
                copied_from_object_id: record.copied_from_object_id.clone(),
                copied_from_version_id: record.copied_from_version_id.clone(),
                copied_from_path: record.copied_from_path.clone(),
            });

            if record.manifest_hash != TOMBSTONE_MANIFEST_HASH
                && seen_manifest_hashes.insert(record.manifest_hash.clone())
            {
                let manifest_bytes = self
                    .load_manifest_payload_by_hash(&record.manifest_hash)
                    .await?
                    .with_context(|| {
                        format!(
                            "missing manifest payload for key={key} version_id={:?} manifest_hash={}",
                            version_id,
                            record.manifest_hash
                        )
                    })?;
                manifests.push(MetadataManifestRecord {
                    manifest_hash: record.manifest_hash.clone(),
                    manifest_bytes,
                });
            }
        } else if let Some(manifest_hash) = current_manifest_hash.clone() {
            let manifest_bytes = self
                .load_manifest_payload_by_hash(&manifest_hash)
                .await?
                .with_context(|| {
                    format!("missing manifest payload for key={key} manifest_hash={manifest_hash}")
                })?;
            manifests.push(MetadataManifestRecord {
                manifest_hash,
                manifest_bytes,
            });
        } else {
            return Ok(None);
        }

        Ok(Some(MetadataExportBundle {
            key: key.to_string(),
            object_id,
            current_manifest_hash,
            versions,
            manifests,
        }))
    }

    pub async fn read_chunk_payload(&self, hash: &str) -> Result<Option<Bytes>> {
        let chunk_path = chunk_path_for_hash(&self.chunks_dir, hash);
        if !fs::try_exists(&chunk_path).await? {
            return Ok(None);
        }

        let payload = fs::read(&chunk_path).await?;
        let actual_hash = hash_hex(&payload);
        if actual_hash != hash {
            bail!("chunk hash mismatch: expected={hash} actual={actual_hash}");
        }
        Ok(Some(Bytes::from(payload)))
    }

    async fn mark_manifest_locally_owned(&self, manifest_hash: &str) -> Result<()> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(());
        }

        self.metadata_store
            .mark_manifest_locally_owned(manifest_hash, unix_ts())
            .await?;

        if let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? {
            for chunk in manifest.chunks {
                self.metadata_store
                    .delete_cached_chunk_record(&chunk.hash)
                    .await?;
            }
        }

        Ok(())
    }

    pub(crate) async fn note_cached_chunk_fetch(
        &self,
        hash: &str,
        size_bytes: usize,
        source_node_id: Option<&str>,
    ) -> Result<()> {
        let now = unix_ts();
        let mut record = self
            .metadata_store
            .load_cached_chunk_record(hash)
            .await?
            .unwrap_or(CachedChunkRecord {
                hash: hash.to_string(),
                size_bytes: size_bytes as u64,
                first_cached_unix: now,
                last_access_unix: now,
                access_count: 0,
                last_source_node_id: source_node_id.map(ToString::to_string),
                cache_class: READ_THROUGH_CACHE_CLASS.to_string(),
            });
        record.size_bytes = size_bytes as u64;
        record.last_access_unix = now;
        record.access_count = record.access_count.saturating_add(1);
        if let Some(source_node_id) = source_node_id {
            record.last_source_node_id = Some(source_node_id.to_string());
        }
        if record.cache_class.is_empty() {
            record.cache_class = READ_THROUGH_CACHE_CLASS.to_string();
        }
        self.metadata_store
            .persist_cached_chunk_record(&record)
            .await
    }

    pub(crate) async fn touch_cached_chunk_accesses(&self, hashes: &[String]) -> Result<()> {
        let now = unix_ts();
        for hash in hashes {
            let Some(mut record) = self.metadata_store.load_cached_chunk_record(hash).await? else {
                continue;
            };
            record.last_access_unix = now;
            record.access_count = record.access_count.saturating_add(1);
            self.metadata_store
                .persist_cached_chunk_record(&record)
                .await?;
        }
        Ok(())
    }

    async fn collect_owned_referenced_manifest_hashes(&self) -> Result<HashSet<String>> {
        let referenced = self.collect_referenced_manifest_hashes().await?;
        let owned = self
            .metadata_store
            .list_locally_owned_manifests()
            .await?
            .into_iter()
            .collect::<HashSet<_>>();
        Ok(referenced
            .into_iter()
            .filter(|manifest_hash| owned.contains(manifest_hash))
            .collect())
    }

    pub async fn ingest_chunk(&self, hash: &str, payload: &[u8]) -> Result<bool> {
        self.chunk_ingestor.ingest_chunk(hash, payload).await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn ingest_chunk_auto(&self, payload: &[u8]) -> Result<(String, bool)> {
        self.chunk_ingestor.ingest_chunk_auto(payload).await
    }

    pub async fn import_replica_manifest(
        &mut self,
        key: &str,
        version_id: Option<&str>,
        parent_version_ids: &[String],
        state: VersionConsistencyState,
        manifest_hash: &str,
        manifest_payload: &[u8],
    ) -> Result<String> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            let object_id = if let Some(object_id) = self.object_id_for_key(key) {
                object_id
            } else if let Some(object_id) = self.resolve_object_id_for_key_history(key).await? {
                object_id
            } else {
                generate_object_id()
            };
            let mut index = self
                .load_version_index_by_object_id(&object_id)
                .await?
                .unwrap_or_else(|| empty_version_index(&object_id));

            let resolved_version_id = version_id
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("rep-{}-tombstone", unix_ts_nanos()));

            if let Some(existing) = index.versions.get(&resolved_version_id) {
                if existing.manifest_hash != TOMBSTONE_MANIFEST_HASH {
                    bail!(
                        "version id collision for key={key} version_id={resolved_version_id}: different manifest"
                    );
                }
                return Ok(resolved_version_id);
            }

            index.versions.insert(
                resolved_version_id.clone(),
                FileVersionRecord {
                    version_id: resolved_version_id.clone(),
                    object_id: object_id.clone(),
                    manifest_hash: TOMBSTONE_MANIFEST_HASH.to_string(),
                    logical_path: Some(key.to_string()),
                    parent_version_ids: parent_version_ids.to_vec(),
                    state,
                    created_at_unix: unix_ts(),
                    copied_from_object_id: None,
                    copied_from_version_id: None,
                    copied_from_path: None,
                },
            );

            index.head_version_ids = recompute_head_version_ids(&index);
            index.preferred_head_version_id = choose_preferred_head(&index);

            self.persist_version_index_by_object_id(&object_id, &index)
                .await?;
            self.sync_current_state_for_key_from_index(key, &index)?;
            self.persist_current_state().await?;
            self.create_snapshot().await?;

            return Ok(resolved_version_id);
        }

        let computed_manifest_hash = hash_hex(manifest_payload);
        if computed_manifest_hash != manifest_hash {
            bail!(
                "manifest hash mismatch: expected={manifest_hash} actual={computed_manifest_hash}"
            );
        }

        let manifest = serde_json::from_slice::<ObjectManifest>(manifest_payload)
            .context("invalid replication manifest payload")?;

        if manifest.key != key {
            bail!(
                "replication manifest key mismatch: expected={key} actual={}",
                manifest.key
            );
        }

        for chunk in &manifest.chunks {
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
            if !fs::try_exists(&chunk_path).await? {
                bail!("manifest references missing chunk hash={}", chunk.hash);
            }

            let metadata = fs::metadata(&chunk_path).await?;
            if metadata.len() != chunk.size_bytes as u64 {
                bail!(
                    "manifest chunk size mismatch hash={} expected={} actual={}",
                    chunk.hash,
                    chunk.size_bytes,
                    metadata.len()
                );
            }
        }

        let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));
        if !fs::try_exists(&manifest_path).await? {
            write_atomic(&manifest_path, manifest_payload).await?;
        }
        self.mark_manifest_locally_owned(manifest_hash).await?;

        let object_id = self
            .object_id_for_key(key)
            .unwrap_or_else(generate_object_id);
        let mut index = self
            .load_version_index_by_object_id(&object_id)
            .await?
            .unwrap_or_else(|| empty_version_index(&object_id));

        let resolved_version_id = version_id
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("rep-{}-{}", unix_ts_nanos(), &manifest_hash[..12]));

        if let Some(existing) = index.versions.get(&resolved_version_id) {
            if existing.manifest_hash != manifest_hash {
                bail!(
                    "version id collision for key={key} version_id={resolved_version_id}: different manifest"
                );
            }

            return Ok(resolved_version_id);
        }

        let record = FileVersionRecord {
            version_id: resolved_version_id.clone(),
            object_id: object_id.clone(),
            manifest_hash: manifest_hash.to_string(),
            logical_path: Some(key.to_string()),
            parent_version_ids: parent_version_ids.to_vec(),
            state,
            created_at_unix: unix_ts(),
            copied_from_object_id: None,
            copied_from_version_id: None,
            copied_from_path: None,
        };

        index.versions.insert(resolved_version_id.clone(), record);

        index.head_version_ids = recompute_head_version_ids(&index);
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;
        self.sync_current_state_for_key_from_index(key, &index)?;
        self.persist_current_state().await?;
        self.create_snapshot().await?;

        Ok(resolved_version_id)
    }

    pub async fn import_metadata_bundle(&mut self, bundle: &MetadataExportBundle) -> Result<bool> {
        let mut changed = false;

        for manifest in &bundle.manifests {
            if manifest.manifest_hash == TOMBSTONE_MANIFEST_HASH {
                continue;
            }

            let computed_manifest_hash = hash_hex(&manifest.manifest_bytes);
            if computed_manifest_hash != manifest.manifest_hash {
                bail!(
                    "metadata manifest hash mismatch: expected={} actual={computed_manifest_hash}",
                    manifest.manifest_hash
                );
            }

            let _: ObjectManifest = serde_json::from_slice(&manifest.manifest_bytes)
                .context("invalid metadata manifest payload")?;

            let manifest_path = self
                .manifests_dir
                .join(format!("{}.json", manifest.manifest_hash));
            if !fs::try_exists(&manifest_path).await? {
                write_atomic(&manifest_path, &manifest.manifest_bytes).await?;
                changed = true;
            }
        }

        let mut current_state_changed = false;

        if !bundle.versions.is_empty() {
            let object_id = bundle.object_id.clone().unwrap_or_else(generate_object_id);
            let mut index = self
                .load_version_index_by_object_id(&object_id)
                .await?
                .unwrap_or_else(|| empty_version_index(&object_id));
            let mut index_changed = false;

            for version in &bundle.versions {
                let record = FileVersionRecord {
                    version_id: version.version_id.clone(),
                    object_id: object_id.clone(),
                    manifest_hash: version.manifest_hash.clone(),
                    logical_path: version.logical_path.clone(),
                    parent_version_ids: version.parent_version_ids.clone(),
                    state: version.state.clone(),
                    created_at_unix: version.created_at_unix,
                    copied_from_object_id: version.copied_from_object_id.clone(),
                    copied_from_version_id: version.copied_from_version_id.clone(),
                    copied_from_path: version.copied_from_path.clone(),
                };

                match index.versions.get(&version.version_id) {
                    Some(existing)
                        if existing.manifest_hash == record.manifest_hash
                            && existing.logical_path == record.logical_path
                            && existing.parent_version_ids == record.parent_version_ids
                            && existing.state == record.state
                            && existing.created_at_unix == record.created_at_unix
                            && existing.copied_from_object_id == record.copied_from_object_id
                            && existing.copied_from_version_id == record.copied_from_version_id
                            && existing.copied_from_path == record.copied_from_path => {}
                    Some(_) => {
                        bail!(
                            "metadata version collision for key={} version_id={}",
                            bundle.key,
                            version.version_id
                        );
                    }
                    None => {
                        index.versions.insert(version.version_id.clone(), record);
                        index_changed = true;
                    }
                }
            }

            if index_changed {
                index.head_version_ids = recompute_head_version_ids(&index);
                index.preferred_head_version_id = choose_preferred_head(&index);
                self.persist_version_index_by_object_id(&object_id, &index)
                    .await?;
                changed = true;
            }

            let preferred_logical_path = index
                .preferred_head_version_id
                .as_ref()
                .and_then(|version_id| index.versions.get(version_id))
                .and_then(|record| record.logical_path.as_deref());
            let current_key = preferred_logical_path.unwrap_or(bundle.key.as_str());
            let before_manifest = self.current_state.objects.get(current_key).cloned();
            let before_object_id = self.current_state.object_ids.get(current_key).cloned();
            self.sync_current_state_for_key_from_index(current_key, &index)?;
            let stale_keys: Vec<String> = self
                .current_state
                .object_ids
                .iter()
                .filter_map(|(key, current_object_id)| {
                    if current_object_id != &object_id {
                        return None;
                    }
                    if Some(key.as_str()) == preferred_logical_path {
                        return None;
                    }
                    Some(key.clone())
                })
                .collect();
            let removed_stale_keys = !stale_keys.is_empty();
            for stale_key in stale_keys {
                self.current_state.objects.remove(&stale_key);
                self.current_state.object_ids.remove(&stale_key);
            }
            if self.current_state.objects.get(current_key).cloned() != before_manifest
                || self.current_state.object_ids.get(current_key).cloned() != before_object_id
                || removed_stale_keys
            {
                current_state_changed = true;
            }
        } else if let Some(manifest_hash) = bundle.current_manifest_hash.as_ref() {
            let object_id = bundle.object_id.clone().unwrap_or_else(generate_object_id);
            if self.current_state.objects.get(&bundle.key) != Some(manifest_hash)
                || self.current_state.object_ids.get(&bundle.key) != Some(&object_id)
            {
                self.current_state
                    .objects
                    .insert(bundle.key.clone(), manifest_hash.clone());
                self.current_state
                    .object_ids
                    .insert(bundle.key.clone(), object_id);
                current_state_changed = true;
            }
        }

        if current_state_changed {
            self.persist_current_state().await?;
            changed = true;
        }

        Ok(changed)
    }

    pub async fn drop_replica_subject(
        &mut self,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<bool> {
        let Some(version_id) = version_id else {
            return Ok(false);
        };

        let Some(object_id) = self.object_id_for_key(key) else {
            return Ok(false);
        };

        let Some(mut index) = self.load_version_index_by_object_id(&object_id).await? else {
            return Ok(false);
        };

        if index.versions.remove(version_id).is_none() {
            return Ok(false);
        }

        index.head_version_ids = recompute_head_version_ids(&index);
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;
        self.sync_current_state_for_key_from_index(key, &index)?;
        self.persist_current_state().await?;
        self.create_snapshot().await?;

        Ok(true)
    }

    pub async fn has_reconcile_marker(
        &self,
        source_node_id: &str,
        key: &str,
        source_version_id: &str,
    ) -> Result<bool> {
        self.metadata_store
            .has_reconcile_marker(source_node_id, key, source_version_id)
            .await
    }

    pub async fn mark_reconciled(
        &self,
        source_node_id: &str,
        key: &str,
        source_version_id: &str,
        local_version_id: Option<&str>,
    ) -> Result<()> {
        let marker = ReconcileMarker {
            source_node_id: source_node_id.to_string(),
            key: key.to_string(),
            source_version_id: source_version_id.to_string(),
            local_version_id: local_version_id.map(ToString::to_string),
            imported_at_unix: unix_ts(),
        };
        self.metadata_store.mark_reconciled(&marker).await
    }

    pub async fn list_provisional_versions(&self) -> Result<Vec<ReconcileVersionEntry>> {
        let mut output = Vec::new();
        let mut paths_by_object_id: HashMap<String, Vec<String>> = HashMap::new();
        for (path, object_id) in &self.current_state.object_ids {
            paths_by_object_id
                .entry(object_id.clone())
                .or_default()
                .push(path.clone());
        }

        for index in self.load_all_version_indexes().await? {
            for record in index.versions.values() {
                if record.state != VersionConsistencyState::Provisional {
                    continue;
                }

                if let Some(paths) = paths_by_object_id.get(&record.object_id) {
                    for key in paths {
                        output.push(ReconcileVersionEntry {
                            key: key.clone(),
                            version_id: record.version_id.clone(),
                            manifest_hash: record.manifest_hash.clone(),
                            parent_version_ids: record.parent_version_ids.clone(),
                            state: record.state.clone(),
                            created_at_unix: record.created_at_unix,
                        });
                    }
                }
            }
        }

        output.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| a.created_at_unix.cmp(&b.created_at_unix))
                .then_with(|| a.version_id.cmp(&b.version_id))
        });

        Ok(output)
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

    async fn load_manifest_payload_by_hash(&self, manifest_hash: &str) -> Result<Option<Vec<u8>>> {
        let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));
        if !fs::try_exists(&manifest_path).await? {
            return Ok(None);
        }
        Ok(Some(fs::read(&manifest_path).await?))
    }

    async fn local_chunk_matches_ref(&self, chunk: &ChunkRef) -> Result<bool> {
        let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
        if !fs::try_exists(&chunk_path).await? {
            return Ok(false);
        }
        let payload = fs::read(&chunk_path).await?;
        if payload.len() != chunk.size_bytes {
            return Ok(false);
        }
        Ok(hash_hex(&payload) == chunk.hash)
    }

    #[cfg(test)]
    async fn manifest_is_fully_local(&self, manifest_hash: &str) -> Result<bool> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(true);
        }

        let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
            return Ok(false);
        };

        for chunk in &manifest.chunks {
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
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

    async fn clone_manifest_for_key(&self, manifest_hash: &str, key: &str) -> Result<String> {
        let Some(mut manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
            bail!("missing manifest for hash={manifest_hash}");
        };
        manifest.key = key.to_string();

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let cloned_manifest_hash = hash_hex(&manifest_bytes);
        let manifest_path = self
            .manifests_dir
            .join(format!("{cloned_manifest_hash}.json"));
        if !fs::try_exists(&manifest_path).await? {
            write_atomic(&manifest_path, &manifest_bytes).await?;
        }
        self.mark_manifest_locally_owned(&cloned_manifest_hash)
            .await?;

        Ok(cloned_manifest_hash)
    }

    async fn read_object_by_manifest_hash(
        &self,
        manifest_hash: &str,
    ) -> std::result::Result<Bytes, StoreReadError> {
        let Some(manifest) = self
            .load_manifest_by_hash(manifest_hash)
            .await
            .map_err(StoreReadError::Internal)?
        else {
            return Err(StoreReadError::Corrupt(format!(
                "manifest missing for hash={manifest_hash}"
            )));
        };

        let mut assembled = BytesMut::with_capacity(manifest.total_size_bytes);

        for chunk in manifest.chunks {
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
            if !fs::try_exists(&chunk_path)
                .await
                .map_err(|err| StoreReadError::Internal(err.into()))?
            {
                return Err(StoreReadError::Corrupt(format!(
                    "missing chunk hash={}",
                    chunk.hash
                )));
            }

            let payload = fs::read(&chunk_path)
                .await
                .map_err(|err| StoreReadError::Internal(err.into()))?;

            if payload.len() != chunk.size_bytes {
                return Err(StoreReadError::Corrupt(format!(
                    "size mismatch for chunk hash={} expected={} actual={}",
                    chunk.hash,
                    chunk.size_bytes,
                    payload.len()
                )));
            }

            let actual_hash = hash_hex(&payload);
            if actual_hash != chunk.hash {
                return Err(StoreReadError::Corrupt(format!(
                    "hash mismatch for chunk expected={} actual={}",
                    chunk.hash, actual_hash
                )));
            }

            assembled.extend_from_slice(&payload);
        }

        if assembled.len() != manifest.total_size_bytes {
            return Err(StoreReadError::Corrupt(format!(
                "assembled payload size mismatch key={} expected={} actual={}",
                manifest.key,
                manifest.total_size_bytes,
                assembled.len()
            )));
        }

        Ok(assembled.freeze())
    }

    #[cfg(test)]
    async fn load_cached_media_metadata(
        &self,
        content_fingerprint: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        self.metadata_store
            .load_cached_media_metadata(content_fingerprint)
            .await
    }

    #[cfg(test)]
    fn build_media_cache_record(
        &self,
        manifest_hash: &str,
        content_fingerprint: &str,
        source_size_bytes: usize,
        payload: &[u8],
    ) -> CachedMediaMetadata {
        let generated_at_unix = unix_ts();
        match derive_image_media_cache(
            manifest_hash,
            content_fingerprint,
            source_size_bytes,
            payload,
        ) {
            Ok(derived) => derived,
            Err(err) => CachedMediaMetadata {
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
                error: Some(err.to_string()),
            },
        }
    }

    #[cfg(test)]
    async fn persist_media_cache_record(&self, metadata: &CachedMediaMetadata) -> Result<()> {
        if let Some(thumbnail) = &metadata.thumbnail {
            let thumbnail_path =
                self.media_thumbnail_path(&metadata.content_fingerprint, &thumbnail.profile);
            let payload = self
                .render_thumbnail_payload(
                    &metadata.source_manifest_hash,
                    GRID_THUMBNAIL_MAX_DIMENSION,
                )
                .await?;
            write_atomic(&thumbnail_path, &payload).await?;
        }
        self.metadata_store
            .persist_media_cache_record(metadata)
            .await
    }

    #[cfg(test)]
    async fn render_thumbnail_payload(
        &self,
        manifest_hash: &str,
        max_dimension: u32,
    ) -> Result<Vec<u8>> {
        let payload = self
            .read_object_by_manifest_hash(manifest_hash)
            .await
            .map_err(|err| anyhow::anyhow!("failed to read object for thumbnail render: {err}"))?;
        render_thumbnail_from_payload(&payload, extract_exif_orientation(&payload), max_dimension)
            .map(|rendered| rendered.payload)
    }

    pub fn media_thumbnail_path(&self, content_fingerprint: &str, profile: &str) -> PathBuf {
        self.media_thumbnails_dir
            .join(content_fingerprint)
            .join(format!("{profile}.jpg"))
    }

    pub async fn describe_object(
        &self,
        key: &str,
        snapshot_id: Option<&str>,
        version_id: Option<&str>,
        read_mode: ObjectReadMode,
    ) -> std::result::Result<ObjectReadDescriptor, StoreReadError> {
        let manifest_hash = self
            .resolve_manifest_hash_for_key(key, snapshot_id, version_id, read_mode)
            .await?;
        let Some(manifest) = self
            .load_manifest_by_hash(&manifest_hash)
            .await
            .map_err(StoreReadError::Internal)?
        else {
            return Err(StoreReadError::Corrupt(format!(
                "manifest missing for hash={manifest_hash}"
            )));
        };

        Ok(ObjectReadDescriptor {
            manifest_hash,
            total_size_bytes: manifest.total_size_bytes,
        })
    }

    #[allow(dead_code)]
    pub async fn read_object_range_by_manifest_hash(
        &self,
        manifest_hash: &str,
        start: usize,
        end_exclusive: usize,
    ) -> std::result::Result<Bytes, StoreReadError> {
        if start > end_exclusive {
            return Err(StoreReadError::Internal(anyhow::anyhow!(
                "invalid range start={start} end={end_exclusive}"
            )));
        }

        let Some(manifest) = self
            .load_manifest_by_hash(manifest_hash)
            .await
            .map_err(StoreReadError::Internal)?
        else {
            return Err(StoreReadError::Corrupt(format!(
                "manifest missing for hash={manifest_hash}"
            )));
        };

        if end_exclusive > manifest.total_size_bytes {
            return Err(StoreReadError::Internal(anyhow::anyhow!(
                "range end_exclusive={end_exclusive} exceeds object size={}",
                manifest.total_size_bytes
            )));
        }
        if start == end_exclusive {
            return Ok(Bytes::new());
        }

        let mut assembled = BytesMut::with_capacity(end_exclusive.saturating_sub(start));
        let mut offset = 0usize;

        for chunk in manifest.chunks {
            let chunk_end = offset.saturating_add(chunk.size_bytes);
            if chunk_end <= start {
                offset = chunk_end;
                continue;
            }
            if offset >= end_exclusive {
                break;
            }

            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
            if !fs::try_exists(&chunk_path)
                .await
                .map_err(|err| StoreReadError::Internal(err.into()))?
            {
                return Err(StoreReadError::Corrupt(format!(
                    "missing chunk hash={}",
                    chunk.hash
                )));
            }

            let payload = fs::read(&chunk_path)
                .await
                .map_err(|err| StoreReadError::Internal(err.into()))?;
            if payload.len() != chunk.size_bytes {
                return Err(StoreReadError::Corrupt(format!(
                    "size mismatch for chunk hash={} expected={} actual={}",
                    chunk.hash,
                    chunk.size_bytes,
                    payload.len()
                )));
            }

            let actual_hash = hash_hex(&payload);
            if actual_hash != chunk.hash {
                return Err(StoreReadError::Corrupt(format!(
                    "hash mismatch for chunk expected={} actual={}",
                    chunk.hash, actual_hash
                )));
            }

            let slice_start = start.saturating_sub(offset);
            let slice_end = std::cmp::min(payload.len(), end_exclusive.saturating_sub(offset));
            if slice_start < slice_end {
                assembled.extend_from_slice(&payload[slice_start..slice_end]);
            }
            offset = chunk_end;
        }

        if assembled.len() != end_exclusive.saturating_sub(start) {
            return Err(StoreReadError::Corrupt(format!(
                "assembled range size mismatch expected={} actual={}",
                end_exclusive.saturating_sub(start),
                assembled.len()
            )));
        }

        Ok(assembled.freeze())
    }

    pub async fn plan_object_range_by_manifest_hash(
        &self,
        manifest_hash: &str,
        start: usize,
        end_exclusive: usize,
    ) -> std::result::Result<ObjectStreamPlan, StoreReadError> {
        if start > end_exclusive {
            return Err(StoreReadError::Internal(anyhow::anyhow!(
                "invalid range start={start} end={end_exclusive}"
            )));
        }

        let Some(manifest) = self
            .load_manifest_by_hash(manifest_hash)
            .await
            .map_err(StoreReadError::Internal)?
        else {
            return Err(StoreReadError::Corrupt(format!(
                "manifest missing for hash={manifest_hash}"
            )));
        };

        if end_exclusive > manifest.total_size_bytes {
            return Err(StoreReadError::Internal(anyhow::anyhow!(
                "range end_exclusive={end_exclusive} exceeds object size={}",
                manifest.total_size_bytes
            )));
        }

        let mut planned = Vec::new();
        let mut planned_size = 0usize;
        let mut offset = 0usize;

        for chunk in manifest.chunks {
            let chunk_end = offset.saturating_add(chunk.size_bytes);
            if chunk_end <= start {
                offset = chunk_end;
                continue;
            }
            if offset >= end_exclusive {
                break;
            }

            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
            let metadata = fs::metadata(&chunk_path).await.map_err(|err| {
                if err.kind() == std::io::ErrorKind::NotFound {
                    StoreReadError::Corrupt(format!("missing chunk hash={}", chunk.hash))
                } else {
                    StoreReadError::Internal(err.into())
                }
            })?;
            if metadata.len() != chunk.size_bytes as u64 {
                return Err(StoreReadError::Corrupt(format!(
                    "size mismatch for chunk hash={} expected={} actual={}",
                    chunk.hash,
                    chunk.size_bytes,
                    metadata.len()
                )));
            }
            let is_valid = self
                .local_chunk_matches_ref(&chunk)
                .await
                .map_err(StoreReadError::Internal)?;
            if !is_valid {
                return Err(StoreReadError::Corrupt(format!(
                    "hash mismatch for chunk expected={}",
                    chunk.hash
                )));
            }

            let slice_start = start.saturating_sub(offset);
            let slice_end = std::cmp::min(chunk.size_bytes, end_exclusive.saturating_sub(offset));
            if slice_start < slice_end {
                let len = slice_end - slice_start;
                planned_size = planned_size.saturating_add(len);
                planned.push(ObjectStreamChunkPlan {
                    hash: chunk.hash,
                    path: chunk_path,
                    start: slice_start,
                    len,
                });
            }

            offset = chunk_end;
        }

        if planned_size != end_exclusive.saturating_sub(start) {
            return Err(StoreReadError::Corrupt(format!(
                "planned range size mismatch expected={} actual={planned_size}",
                end_exclusive.saturating_sub(start)
            )));
        }

        Ok(ObjectStreamPlan { chunks: planned })
    }

    pub async fn missing_chunks_for_manifest_range(
        &self,
        manifest_hash: &str,
        start: usize,
        end_exclusive: usize,
    ) -> std::result::Result<Vec<ReplicationChunkInfo>, StoreReadError> {
        if start > end_exclusive {
            return Err(StoreReadError::Internal(anyhow::anyhow!(
                "invalid range start={start} end={end_exclusive}"
            )));
        }

        let Some(manifest) = self
            .load_manifest_by_hash(manifest_hash)
            .await
            .map_err(StoreReadError::Internal)?
        else {
            return Err(StoreReadError::Corrupt(format!(
                "manifest missing for hash={manifest_hash}"
            )));
        };

        if end_exclusive > manifest.total_size_bytes {
            return Err(StoreReadError::Internal(anyhow::anyhow!(
                "range end_exclusive={end_exclusive} exceeds object size={}",
                manifest.total_size_bytes
            )));
        }

        let mut missing = Vec::new();
        let mut offset = 0usize;

        for chunk in manifest.chunks {
            let chunk_end = offset.saturating_add(chunk.size_bytes);
            if chunk_end <= start {
                offset = chunk_end;
                continue;
            }
            if offset >= end_exclusive {
                break;
            }

            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
            let is_missing = match fs::metadata(&chunk_path).await {
                Ok(metadata) if metadata.len() == chunk.size_bytes as u64 => !self
                    .local_chunk_matches_ref(&chunk)
                    .await
                    .map_err(StoreReadError::Internal)?,
                Ok(_) => true,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
                Err(err) => return Err(StoreReadError::Internal(err.into())),
            };

            if is_missing {
                missing.push(ReplicationChunkInfo {
                    hash: chunk.hash,
                    size_bytes: chunk.size_bytes,
                });
            }

            offset = chunk_end;
        }

        Ok(missing)
    }

    pub async fn chunk_hashes_for_manifest_range(
        &self,
        manifest_hash: &str,
        start: usize,
        end_exclusive: usize,
    ) -> std::result::Result<Vec<String>, StoreReadError> {
        if start > end_exclusive {
            return Err(StoreReadError::Internal(anyhow::anyhow!(
                "invalid range start={start} end={end_exclusive}"
            )));
        }

        let Some(manifest) = self
            .load_manifest_by_hash(manifest_hash)
            .await
            .map_err(StoreReadError::Internal)?
        else {
            return Err(StoreReadError::Corrupt(format!(
                "manifest missing for hash={manifest_hash}"
            )));
        };

        if end_exclusive > manifest.total_size_bytes {
            return Err(StoreReadError::Internal(anyhow::anyhow!(
                "range end_exclusive={end_exclusive} exceeds object size={}",
                manifest.total_size_bytes
            )));
        }

        let mut hashes = Vec::new();
        let mut offset = 0usize;

        for chunk in manifest.chunks {
            let chunk_end = offset.saturating_add(chunk.size_bytes);
            if chunk_end <= start {
                offset = chunk_end;
                continue;
            }
            if offset >= end_exclusive {
                break;
            }
            hashes.push(chunk.hash);
            offset = chunk_end;
        }

        Ok(hashes)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn get_object(
        &self,
        key: &str,
        snapshot_id: Option<&str>,
        version_id: Option<&str>,
        read_mode: ObjectReadMode,
    ) -> std::result::Result<Bytes, StoreReadError> {
        let manifest_hash = self
            .resolve_manifest_hash_for_key(key, snapshot_id, version_id, read_mode)
            .await?;
        self.read_object_by_manifest_hash(&manifest_hash).await
    }

    pub async fn tombstone_subtree(
        &mut self,
        key: &str,
        options: PutOptions,
    ) -> Result<Vec<TombstonePathResult>> {
        if key.trim().is_empty() {
            bail!("recursive delete key must not be empty");
        }
        if !options.parent_version_ids.is_empty() {
            bail!("recursive delete does not support explicit parent versions");
        }
        if options.explicit_version_id.is_some() {
            bail!("recursive delete does not support explicit version ids");
        }

        let normalized_root = key.trim_end_matches('/');
        let marker_root = format!("{normalized_root}/");
        let mut targets = BTreeSet::new();

        for existing_key in self.current_state.objects.keys() {
            if existing_key == normalized_root
                || existing_key == &marker_root
                || existing_key.starts_with(&marker_root)
            {
                targets.insert(existing_key.clone());
            }
        }

        // Preserve tombstone semantics even when the subtree is already absent.
        if targets.is_empty() {
            targets.insert(key.to_string());
        } else {
            targets.insert(marker_root);
        }

        let mut results = Vec::with_capacity(targets.len());
        let mut per_path_options = options.clone();
        per_path_options.create_snapshot = false;
        for target in targets {
            let version_id = self
                .tombstone_object(&target, per_path_options.clone())
                .await?;
            results.push(TombstonePathResult {
                path: target,
                version_id,
            });
        }

        if options.create_snapshot && !results.is_empty() {
            self.create_snapshot().await?;
        }

        Ok(results)
    }

    pub async fn tombstone_object(&mut self, key: &str, options: PutOptions) -> Result<String> {
        let object_id = self
            .object_id_for_key(key)
            .unwrap_or_else(generate_object_id);
        let mut index = self
            .load_version_index_by_object_id(&object_id)
            .await?
            .unwrap_or_else(|| empty_version_index(&object_id));

        let parent_version_ids = if options.parent_version_ids.is_empty() {
            if options.inherit_preferred_parent {
                index
                    .preferred_head_version_id
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        } else {
            options.parent_version_ids.clone()
        };

        for parent in &parent_version_ids {
            if !index.versions.contains_key(parent) {
                bail!("parent version does not exist for key={key}: {parent}");
            }
        }

        let version_id = options
            .explicit_version_id
            .clone()
            .unwrap_or_else(|| format!("tomb-{}", unix_ts_nanos()));

        if let Some(existing) = index.versions.get(&version_id) {
            if existing.manifest_hash != TOMBSTONE_MANIFEST_HASH {
                bail!(
                    "version id collision for key={key} version_id={version_id}: different manifest"
                );
            }

            self.sync_current_state_for_key_from_index(key, &index)?;
            self.persist_current_state().await?;

            let _snapshot_id = if options.create_snapshot {
                self.create_snapshot().await?
            } else {
                format!("snap-skipped-{version_id}")
            };

            return Ok(existing.version_id.clone());
        }

        let record = FileVersionRecord {
            version_id: version_id.clone(),
            object_id: object_id.clone(),
            manifest_hash: TOMBSTONE_MANIFEST_HASH.to_string(),
            logical_path: Some(key.to_string()),
            parent_version_ids: parent_version_ids.clone(),
            state: options.state.clone(),
            created_at_unix: unix_ts(),
            copied_from_object_id: None,
            copied_from_version_id: None,
            copied_from_path: None,
        };

        index.versions.insert(version_id.clone(), record);

        let mut heads: HashSet<String> = index.head_version_ids.into_iter().collect();
        for parent in &parent_version_ids {
            heads.remove(parent);
        }
        heads.insert(version_id.clone());

        index.head_version_ids = heads.into_iter().collect();
        index.head_version_ids.sort();
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;
        self.sync_current_state_for_key_from_index(key, &index)?;
        self.persist_current_state().await?;

        if options.create_snapshot {
            self.create_snapshot().await?;
        }

        Ok(version_id)
    }

    pub async fn rename_object_path(
        &mut self,
        from_path: &str,
        to_path: &str,
        overwrite: bool,
    ) -> Result<PathMutationResult> {
        if from_path == to_path {
            return Ok(PathMutationResult::Applied);
        }

        let Some(object_id) = self.current_state.object_ids.get(from_path).cloned() else {
            return Ok(PathMutationResult::SourceMissing);
        };
        let Some(_manifest_hash) = self.current_state.objects.get(from_path).cloned() else {
            return Ok(PathMutationResult::SourceMissing);
        };

        if self.current_state.object_ids.contains_key(to_path) {
            if !overwrite {
                return Ok(PathMutationResult::TargetExists);
            }
            return Ok(PathMutationResult::TargetExists);
        }

        let Some(mut index) = self.load_version_index_by_object_id(&object_id).await? else {
            return Ok(PathMutationResult::SourceMissing);
        };
        let Some(source_head_version_id) = index.preferred_head_version_id.clone() else {
            return Ok(PathMutationResult::SourceMissing);
        };
        let Some(source_head) = index.versions.get(&source_head_version_id).cloned() else {
            return Ok(PathMutationResult::SourceMissing);
        };

        if source_head.manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(PathMutationResult::SourceMissing);
        }

        let renamed_manifest_hash = self
            .clone_manifest_for_key(&source_head.manifest_hash, to_path)
            .await?;
        let renamed_version_id =
            format!("ren-{}-{}", unix_ts_nanos(), &renamed_manifest_hash[..12]);
        let source_head_version_id = source_head.version_id.clone();

        for record in index.versions.values_mut() {
            record.logical_path = Some(to_path.to_string());
        }
        index.versions.insert(
            renamed_version_id.clone(),
            FileVersionRecord {
                version_id: renamed_version_id.clone(),
                object_id: object_id.clone(),
                manifest_hash: renamed_manifest_hash.clone(),
                logical_path: Some(to_path.to_string()),
                parent_version_ids: vec![source_head_version_id.clone()],
                state: source_head.state.clone(),
                created_at_unix: unix_ts(),
                copied_from_object_id: None,
                copied_from_version_id: None,
                copied_from_path: None,
            },
        );
        let mut heads: HashSet<String> = index.head_version_ids.into_iter().collect();
        heads.remove(&source_head.version_id);
        heads.insert(renamed_version_id);
        index.head_version_ids = heads.into_iter().collect();
        index.head_version_ids.sort();
        index.preferred_head_version_id = choose_preferred_head(&index);
        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;

        self.current_state.object_ids.remove(from_path);
        self.current_state.objects.remove(from_path);
        self.current_state
            .object_ids
            .insert(to_path.to_string(), object_id);
        self.current_state
            .objects
            .insert(to_path.to_string(), renamed_manifest_hash);

        let tombstone_object_id = generate_object_id();
        let tombstone_version_id = format!("rename-tomb-{}", unix_ts_nanos());
        let tombstone_record = FileVersionRecord {
            version_id: tombstone_version_id.clone(),
            object_id: tombstone_object_id.clone(),
            manifest_hash: TOMBSTONE_MANIFEST_HASH.to_string(),
            logical_path: Some(from_path.to_string()),
            parent_version_ids: vec![source_head_version_id.clone()],
            state: source_head.state,
            created_at_unix: unix_ts(),
            copied_from_object_id: Some(index.object_id.clone()),
            copied_from_version_id: Some(source_head_version_id),
            copied_from_path: Some(from_path.to_string()),
        };
        let mut tombstone_index = empty_version_index(&tombstone_object_id);
        tombstone_index
            .versions
            .insert(tombstone_version_id.clone(), tombstone_record);
        tombstone_index.head_version_ids = vec![tombstone_version_id];
        tombstone_index.preferred_head_version_id = choose_preferred_head(&tombstone_index);
        self.persist_version_index_by_object_id(&tombstone_object_id, &tombstone_index)
            .await?;

        self.persist_current_state().await?;
        self.create_snapshot().await?;

        Ok(PathMutationResult::Applied)
    }

    pub async fn copy_object_path(
        &mut self,
        from_path: &str,
        to_path: &str,
        overwrite: bool,
    ) -> Result<PathMutationResult> {
        if from_path == to_path {
            return Ok(PathMutationResult::Applied);
        }

        let Some(source_object_id) = self.current_state.object_ids.get(from_path).cloned() else {
            return Ok(PathMutationResult::SourceMissing);
        };

        if self.current_state.object_ids.contains_key(to_path) {
            if !overwrite {
                return Ok(PathMutationResult::TargetExists);
            }
            return Ok(PathMutationResult::TargetExists);
        }

        let Some(source_index) = self
            .load_version_index_by_object_id(&source_object_id)
            .await?
        else {
            return Ok(PathMutationResult::SourceMissing);
        };
        let Some(source_head_version_id) = source_index.preferred_head_version_id.clone() else {
            return Ok(PathMutationResult::SourceMissing);
        };
        let Some(source_head) = source_index.versions.get(&source_head_version_id) else {
            return Ok(PathMutationResult::SourceMissing);
        };

        if source_head.manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(PathMutationResult::SourceMissing);
        }

        let copied_manifest_hash = self
            .clone_manifest_for_key(&source_head.manifest_hash, to_path)
            .await?;
        let copied_object_id = generate_object_id();
        let copied_version_id = format!("copy-{}-{}", unix_ts_nanos(), &copied_manifest_hash[..12]);
        let copied_record = FileVersionRecord {
            version_id: copied_version_id.clone(),
            object_id: copied_object_id.clone(),
            manifest_hash: copied_manifest_hash.clone(),
            logical_path: Some(to_path.to_string()),
            parent_version_ids: Vec::new(),
            state: source_head.state.clone(),
            created_at_unix: unix_ts(),
            copied_from_object_id: Some(source_object_id),
            copied_from_version_id: Some(source_head.version_id.clone()),
            copied_from_path: Some(from_path.to_string()),
        };

        let mut copied_index = empty_version_index(&copied_object_id);
        copied_index
            .versions
            .insert(copied_version_id.clone(), copied_record);
        copied_index.head_version_ids = vec![copied_version_id];
        copied_index.preferred_head_version_id = choose_preferred_head(&copied_index);
        self.persist_version_index_by_object_id(&copied_object_id, &copied_index)
            .await?;

        self.current_state
            .object_ids
            .insert(to_path.to_string(), copied_object_id);
        self.current_state
            .objects
            .insert(to_path.to_string(), copied_manifest_hash);
        self.persist_current_state().await?;
        self.create_snapshot().await?;

        Ok(PathMutationResult::Applied)
    }

    pub async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        self.metadata_store.list_snapshot_infos().await
    }

    pub async fn load_current_storage_stats(&self) -> Result<Option<StorageStatsSample>> {
        self.metadata_store.load_current_storage_stats().await
    }

    async fn load_storage_stats_state(&self) -> Result<Option<StorageStatsState>> {
        self.metadata_store.load_storage_stats_state().await
    }

    async fn persist_storage_stats_state(&self, state: &StorageStatsState) -> Result<()> {
        self.metadata_store.persist_storage_stats_state(state).await
    }

    pub async fn list_storage_stats_history(
        &self,
        limit: usize,
    ) -> Result<Vec<StorageStatsSample>> {
        self.metadata_store.list_storage_stats_history(limit).await
    }

    #[cfg(test)]
    pub async fn persist_storage_stats_sample(&self, sample: &StorageStatsSample) -> Result<()> {
        self.storage_stats_collector()
            .persist_storage_stats_sample(sample)
            .await
    }

    #[cfg(test)]
    pub async fn prune_storage_stats_history_before(
        &self,
        collected_before_unix: u64,
    ) -> Result<()> {
        self.storage_stats_collector()
            .prune_storage_stats_history_before(collected_before_unix)
            .await
    }

    async fn reconcile_chunk_store_bytes_state(&self) -> Result<StorageStatsState> {
        let state = StorageStatsState {
            chunk_store_bytes: directory_size_bytes(&self.chunks_dir).await?,
            last_reconciled_unix: unix_ts(),
        };
        self.persist_storage_stats_state(&state).await?;
        Ok(state)
    }

    #[cfg(test)]
    pub async fn current_chunk_store_bytes(
        &self,
        reconcile_max_age_secs: Option<u64>,
    ) -> Result<u64> {
        self.storage_stats_collector()
            .current_chunk_store_bytes(reconcile_max_age_secs)
            .await
    }

    async fn note_chunk_store_delta(&self, delta_bytes: i64) -> Result<u64> {
        let _guard = self.storage_stats_lock.lock().await;

        let Some(mut state) = self.load_storage_stats_state().await? else {
            return Ok(self
                .reconcile_chunk_store_bytes_state()
                .await?
                .chunk_store_bytes);
        };

        if delta_bytes >= 0 {
            state.chunk_store_bytes = state.chunk_store_bytes.saturating_add(delta_bytes as u64);
        } else {
            state.chunk_store_bytes = state
                .chunk_store_bytes
                .saturating_sub(delta_bytes.unsigned_abs());
        }

        self.persist_storage_stats_state(&state).await?;
        Ok(state.chunk_store_bytes)
    }

    #[cfg(test)]
    pub async fn collect_storage_stats_sample(&self) -> Result<StorageStatsSample> {
        self.storage_stats_collector()
            .collect_storage_stats_sample()
            .await
    }

    pub async fn cleanup_unreferenced(
        &self,
        retention_secs: u64,
        dry_run: bool,
    ) -> Result<CleanupReport> {
        let now = unix_ts();
        let referenced_manifests = self.collect_referenced_manifest_hashes().await?;
        let owned_referenced_manifests = self.collect_owned_referenced_manifest_hashes().await?;
        let all_manifests = self.load_all_manifests().await?;
        let cached_chunk_records = self.metadata_store.list_cached_chunk_records().await?;
        let tracked_cached_chunks = cached_chunk_records.len();
        let cached_chunk_hashes = cached_chunk_records
            .iter()
            .map(|record| record.hash.clone())
            .collect::<HashSet<_>>();

        let mut retained_manifests = referenced_manifests.clone();
        let mut skipped_recent_manifests = 0usize;
        let mut deleted_manifests = 0usize;

        for manifest_hash in all_manifests.keys() {
            if referenced_manifests.contains(manifest_hash) {
                continue;
            }

            let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));
            let metadata = match fs::metadata(&manifest_path).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
            let age_secs = modified
                .duration_since(UNIX_EPOCH)
                .map(|d| now.saturating_sub(d.as_secs()))
                .unwrap_or(0);
            if age_secs < retention_secs {
                retained_manifests.insert(manifest_hash.clone());
                skipped_recent_manifests += 1;
                continue;
            }

            if dry_run {
                continue;
            }

            if fs::try_exists(&manifest_path).await? {
                fs::remove_file(&manifest_path).await?;
                self.metadata_store
                    .delete_locally_owned_manifest(manifest_hash)
                    .await?;
                deleted_manifests += 1;
            }
        }

        let mut protected_chunks = HashSet::<String>::new();
        let mut protected_media_fingerprints = HashSet::<String>::new();
        for manifest_hash in &retained_manifests {
            if let Some(manifest) = all_manifests.get(manifest_hash) {
                protected_media_fingerprints.insert(content_fingerprint_from_manifest(manifest));
                if owned_referenced_manifests.contains(manifest_hash) {
                    for chunk in &manifest.chunks {
                        protected_chunks.insert(chunk.hash.clone());
                    }
                }
            }
        }

        let mut skipped_recent_chunks = 0usize;
        let mut deleted_chunks = 0usize;
        let mut deleted_cached_chunks = 0usize;
        let mut deleted_cached_chunk_records = 0usize;

        let chunk_files = self.collect_chunk_file_paths().await?;
        for chunk_path in chunk_files {
            let chunk_hash = match chunk_path.file_name().and_then(|n| n.to_str()) {
                Some(hash) => hash.to_string(),
                None => continue,
            };

            if protected_chunks.contains(&chunk_hash) {
                continue;
            }

            let metadata = fs::metadata(&chunk_path).await?;
            let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
            let age_secs = modified
                .duration_since(UNIX_EPOCH)
                .map(|d| now.saturating_sub(d.as_secs()))
                .unwrap_or(0);

            if age_secs < retention_secs {
                skipped_recent_chunks += 1;
                continue;
            }

            if dry_run {
                continue;
            }

            let chunk_size_bytes = metadata.len();
            fs::remove_file(&chunk_path).await?;
            self.note_chunk_store_delta(-(chunk_size_bytes as i64))
                .await?;
            if cached_chunk_hashes.contains(&chunk_hash) {
                self.metadata_store
                    .delete_cached_chunk_record(&chunk_hash)
                    .await?;
                deleted_cached_chunks += 1;
                deleted_cached_chunk_records += 1;
            }
            deleted_chunks += 1;
        }

        if !dry_run {
            for record in cached_chunk_records {
                if protected_chunks.contains(&record.hash) {
                    self.metadata_store
                        .delete_cached_chunk_record(&record.hash)
                        .await?;
                    deleted_cached_chunk_records += 1;
                    continue;
                }

                let chunk_path = chunk_path_for_hash(&self.chunks_dir, &record.hash);
                if !fs::try_exists(&chunk_path).await? {
                    self.metadata_store
                        .delete_cached_chunk_record(&record.hash)
                        .await?;
                    deleted_cached_chunk_records += 1;
                }
            }
        }

        for content_fingerprint in self.list_media_cache_fingerprints().await? {
            if protected_media_fingerprints.contains(&content_fingerprint) {
                continue;
            }

            if dry_run {
                continue;
            }

            self.metadata_store
                .delete_media_cache_record(&content_fingerprint)
                .await?;

            let thumb_dir = self.media_thumbnails_dir.join(&content_fingerprint);
            if fs::try_exists(&thumb_dir).await? {
                let _ = fs::remove_dir_all(&thumb_dir).await;
            }
        }

        Ok(CleanupReport {
            retention_secs,
            dry_run,
            protected_manifests: referenced_manifests.len(),
            protected_chunks: protected_chunks.len(),
            tracked_cached_chunks,
            skipped_recent_manifests,
            skipped_recent_chunks,
            deleted_manifests,
            deleted_chunks,
            deleted_cached_chunks,
            deleted_cached_chunk_records,
        })
    }

    pub async fn compact_tombstone_indexes(
        &self,
        retention_secs: u64,
        dry_run: bool,
    ) -> Result<TombstoneCompactionReport> {
        let now = unix_ts();
        let bound_object_ids: HashSet<String> =
            self.current_state.object_ids.values().cloned().collect();

        let mut scanned_indexes = 0usize;
        let mut tombstone_head_indexes = 0usize;
        let mut eligible = Vec::<(String, String, u64, FileVersionIndex)>::new();

        for index in self.load_all_version_indexes().await? {
            scanned_indexes += 1;

            let Some(preferred_head_id) = index
                .preferred_head_version_id
                .clone()
                .or_else(|| choose_preferred_head(&index))
            else {
                continue;
            };
            let Some(preferred_head) = index.versions.get(&preferred_head_id) else {
                continue;
            };
            if preferred_head.manifest_hash != TOMBSTONE_MANIFEST_HASH {
                continue;
            }
            tombstone_head_indexes += 1;
            if bound_object_ids.contains(&index.object_id) {
                continue;
            }

            let age_secs = now.saturating_sub(preferred_head.created_at_unix);
            if age_secs < retention_secs {
                continue;
            }

            eligible.push((
                index.object_id.clone(),
                preferred_head.version_id.clone(),
                preferred_head.created_at_unix,
                index,
            ));
        }

        let eligible_indexes = eligible.len();
        if dry_run || eligible.is_empty() {
            return Ok(TombstoneCompactionReport {
                retention_secs,
                dry_run,
                scanned_indexes,
                tombstone_head_indexes,
                eligible_indexes,
                archived_indexes: 0,
                removed_indexes: 0,
                archive_path: None,
            });
        }

        let archive_dir = self.root_dir.join("state").join("tombstone_archive");
        fs::create_dir_all(&archive_dir).await?;
        let archive_file = archive_dir.join(format!("archive-{}.jsonl", unix_ts_nanos()));
        let mut archive_writer = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&archive_file)
            .await
            .with_context(|| format!("failed to create {}", archive_file.display()))?;

        let mut archived_indexes = 0usize;
        let mut removed_indexes = 0usize;
        for (object_id, preferred_tombstone_version_id, tombstone_created_at_unix, index) in
            eligible
        {
            let record = ArchivedTombstoneIndexRecord {
                object_id: object_id.clone(),
                preferred_tombstone_version_id,
                preferred_tombstone_created_at_unix: tombstone_created_at_unix,
                archived_at_unix: now,
                index,
            };
            let mut line = serde_json::to_vec(&record)?;
            line.push(b'\n');
            archive_writer.write_all(&line).await?;
            archived_indexes += 1;

            self.delete_version_index_by_object_id(&object_id).await?;
            removed_indexes += 1;
        }
        archive_writer.flush().await?;

        Ok(TombstoneCompactionReport {
            retention_secs,
            dry_run,
            scanned_indexes,
            tombstone_head_indexes,
            eligible_indexes,
            archived_indexes,
            removed_indexes,
            archive_path: Some(archive_file.to_string_lossy().to_string()),
        })
    }

    pub async fn list_tombstone_archives(&self) -> Result<Vec<TombstoneArchiveFileInfo>> {
        let archive_dir = self.tombstone_archive_dir();
        if !fs::try_exists(&archive_dir).await? {
            return Ok(Vec::new());
        }

        let mut entries = fs::read_dir(&archive_dir).await?;
        let mut files = Vec::<TombstoneArchiveFileInfo>::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
                continue;
            }

            let metadata = fs::metadata(&path).await?;
            let modified_at_unix = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_secs())
                .unwrap_or(0);

            let payload = fs::read(&path).await?;
            let entries = payload
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .count();

            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            files.push(TombstoneArchiveFileInfo {
                file_name: file_name.to_string(),
                path: path.to_string_lossy().to_string(),
                modified_at_unix,
                size_bytes: metadata.len(),
                entries,
            });
        }

        files.sort_by(|left, right| {
            right
                .modified_at_unix
                .cmp(&left.modified_at_unix)
                .then_with(|| left.file_name.cmp(&right.file_name))
        });
        Ok(files)
    }

    pub async fn restore_tombstone_index_from_archive(
        &self,
        object_id: &str,
        archive_file: Option<&str>,
        overwrite: bool,
        dry_run: bool,
    ) -> Result<TombstoneRestoreReport> {
        let archive_candidates = if let Some(file_name) = archive_file {
            vec![self.validate_archive_file(file_name).await?]
        } else {
            self.list_archive_paths().await?
        };

        let mut selected: Option<(String, ArchivedTombstoneIndexRecord)> = None;
        for path in archive_candidates {
            let file_name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_string();

            let payload = fs::read(&path).await?;
            for line in payload
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
            {
                let record = serde_json::from_slice::<ArchivedTombstoneIndexRecord>(line)
                    .with_context(|| {
                        format!("invalid tombstone archive record in {}", path.display())
                    })?;
                if record.object_id != object_id {
                    continue;
                }

                let replace = selected
                    .as_ref()
                    .map(|(_, current)| {
                        (
                            record.archived_at_unix,
                            record.preferred_tombstone_created_at_unix,
                        ) > (
                            current.archived_at_unix,
                            current.preferred_tombstone_created_at_unix,
                        )
                    })
                    .unwrap_or(true);
                if replace {
                    selected = Some((file_name.clone(), record));
                }
            }
        }

        let index_path_string = self.version_index_locator(object_id);
        let index_exists = self.has_version_index(object_id).await?;
        if selected.is_none() {
            return Ok(TombstoneRestoreReport {
                object_id: object_id.to_string(),
                source_archive_file: archive_file.map(ToString::to_string),
                dry_run,
                found: false,
                restored: false,
                skipped_existing: index_exists,
                would_restore: false,
                index_path: index_path_string,
            });
        }

        let (source_archive_file, record) = selected.expect("checked above");
        if index_exists && !overwrite {
            return Ok(TombstoneRestoreReport {
                object_id: object_id.to_string(),
                source_archive_file: Some(source_archive_file),
                dry_run,
                found: true,
                restored: false,
                skipped_existing: true,
                would_restore: false,
                index_path: index_path_string,
            });
        }

        if dry_run {
            return Ok(TombstoneRestoreReport {
                object_id: object_id.to_string(),
                source_archive_file: Some(source_archive_file),
                dry_run,
                found: true,
                restored: false,
                skipped_existing: false,
                would_restore: true,
                index_path: index_path_string,
            });
        }

        self.persist_version_index_by_object_id(object_id, &record.index)
            .await?;
        Ok(TombstoneRestoreReport {
            object_id: object_id.to_string(),
            source_archive_file: Some(source_archive_file),
            dry_run,
            found: true,
            restored: true,
            skipped_existing: false,
            would_restore: false,
            index_path: index_path_string,
        })
    }

    pub async fn purge_tombstone_archives(
        &self,
        retention_secs: u64,
        dry_run: bool,
    ) -> Result<TombstoneArchivePurgeReport> {
        let now = unix_ts();
        let paths = self.list_archive_paths().await?;

        let mut scanned_files = 0usize;
        let mut eligible_files = 0usize;
        let mut deleted_files = 0usize;
        let mut kept_recent_files = 0usize;

        for path in paths {
            scanned_files += 1;
            let metadata = fs::metadata(&path).await?;
            let modified_at = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_secs())
                .unwrap_or(0);
            let age_secs = now.saturating_sub(modified_at);

            if age_secs < retention_secs {
                kept_recent_files += 1;
                continue;
            }

            eligible_files += 1;
            if dry_run {
                continue;
            }

            fs::remove_file(&path).await?;
            deleted_files += 1;
        }

        Ok(TombstoneArchivePurgeReport {
            retention_secs,
            dry_run,
            scanned_files,
            eligible_files,
            deleted_files,
            kept_recent_files,
        })
    }

    pub async fn append_admin_audit_event(&self, event: &AdminAuditEvent) -> Result<()> {
        self.metadata_store.append_admin_audit_event(event).await
    }

    fn object_id_for_key(&self, key: &str) -> Option<String> {
        self.current_state.object_ids.get(key).cloned()
    }

    async fn load_version_index_by_object_id(
        &self,
        object_id: &str,
    ) -> Result<Option<FileVersionIndex>> {
        self.metadata_store
            .load_version_index_by_object_id(object_id)
            .await
    }

    async fn persist_version_index_by_object_id(
        &self,
        object_id: &str,
        index: &FileVersionIndex,
    ) -> Result<()> {
        self.metadata_store
            .persist_version_index_by_object_id(object_id, index)
            .await
    }

    fn sync_current_state_for_key_from_index(
        &mut self,
        key: &str,
        index: &FileVersionIndex,
    ) -> Result<()> {
        let Some(preferred_head) = &index.preferred_head_version_id else {
            self.current_state.objects.remove(key);
            self.current_state.object_ids.remove(key);
            return Ok(());
        };

        let manifest_hash = index
            .versions
            .get(preferred_head)
            .map(|record| record.manifest_hash.clone())
            .with_context(|| {
                format!("preferred head {preferred_head} missing in index for key={key}")
            })?;

        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            self.current_state.objects.remove(key);
            self.current_state.object_ids.remove(key);
            return Ok(());
        }

        self.current_state
            .objects
            .insert(key.to_string(), manifest_hash);
        self.current_state
            .object_ids
            .insert(key.to_string(), index.object_id.clone());
        Ok(())
    }

    async fn persist_current_state(&self) -> Result<()> {
        self.metadata_store
            .persist_current_state(&self.current_state)
            .await
    }

    async fn resolve_object_id_for_key_history(&self, key: &str) -> Result<Option<String>> {
        if let Some(object_id) = self.object_id_for_key(key) {
            return Ok(Some(object_id));
        }

        for index in self.load_all_version_indexes().await? {
            if self.resolve_key_for_version_index(&index).await?.as_deref() == Some(key) {
                return Ok(Some(index.object_id));
            }
        }

        Ok(None)
    }

    async fn resolve_key_for_version_index(
        &self,
        index: &FileVersionIndex,
    ) -> Result<Option<String>> {
        if let Some(preferred_head) = index
            .preferred_head_version_id
            .as_ref()
            .and_then(|version_id| index.versions.get(version_id))
            .and_then(|record| record.logical_path.clone())
        {
            return Ok(Some(preferred_head));
        }

        if let Some(any_logical_path) = index
            .versions
            .values()
            .find_map(|record| record.logical_path.clone())
        {
            return Ok(Some(any_logical_path));
        }

        for record in index.versions.values() {
            if record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
                continue;
            }

            if let Some(manifest) = self.load_manifest_by_hash(&record.manifest_hash).await? {
                return Ok(Some(manifest.key));
            }
        }

        Ok(None)
    }

    async fn create_snapshot(&self) -> Result<String> {
        let created_at_unix = unix_ts();
        let object_map_payload = serde_json::to_vec(&(
            self.current_state.objects.clone(),
            self.current_state.object_ids.clone(),
        ))?;
        let state_hash = hash_hex(&object_map_payload);
        let snapshot_id = format!("snap-{}-{}", unix_ts_nanos(), &state_hash[..12]);

        let manifest = SnapshotManifest {
            id: snapshot_id.clone(),
            created_at_unix,
            objects: self.current_state.objects.clone(),
            object_ids: self.current_state.object_ids.clone(),
        };

        self.metadata_store
            .persist_snapshot_manifest(&manifest)
            .await?;

        Ok(snapshot_id)
    }

    async fn read_snapshot(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
        self.load_snapshot_manifest(snapshot_id).await
    }

    async fn collect_referenced_manifest_hashes(&self) -> Result<HashSet<String>> {
        let mut referenced = HashSet::<String>::new();

        for manifest_hash in self.current_state.objects.values() {
            referenced.insert(manifest_hash.clone());
        }

        for snapshot in self.load_all_snapshots().await? {
            for manifest_hash in snapshot.objects.values() {
                referenced.insert(manifest_hash.clone());
            }
        }

        for index in self.load_all_version_indexes().await? {
            for version in index.versions.values() {
                referenced.insert(version.manifest_hash.clone());
            }
        }

        Ok(referenced)
    }

    async fn load_all_manifests(&self) -> Result<HashMap<String, ObjectManifest>> {
        let mut manifests = HashMap::<String, ObjectManifest>::new();
        let mut entries = fs::read_dir(&self.manifests_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            let payload = fs::read(&path).await?;
            let manifest = serde_json::from_slice::<ObjectManifest>(&payload)
                .with_context(|| format!("invalid manifest {}", path.display()))?;
            manifests.insert(file_stem.to_string(), manifest);
        }

        Ok(manifests)
    }

    async fn collect_chunk_file_paths(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::<PathBuf>::new();
        let mut dirs = vec![self.chunks_dir.clone()];

        while let Some(dir) = dirs.pop() {
            let mut entries = match fs::read_dir(&dir).await {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let ftype = entry.file_type().await?;
                if ftype.is_dir() {
                    dirs.push(path);
                } else if ftype.is_file() {
                    files.push(path);
                }
            }
        }

        Ok(files)
    }

    fn version_index_locator(&self, object_id: &str) -> String {
        format!(
            "{}#version_indexes/{}",
            self.metadata_db_path.display(),
            object_id
        )
    }

    fn tombstone_archive_dir(&self) -> PathBuf {
        self.root_dir.join("state").join("tombstone_archive")
    }

    async fn load_all_version_indexes(&self) -> Result<Vec<FileVersionIndex>> {
        self.metadata_store.load_all_version_indexes().await
    }

    async fn load_all_snapshots(&self) -> Result<Vec<SnapshotManifest>> {
        self.metadata_store.load_all_snapshots().await
    }

    async fn has_version_index(&self, object_id: &str) -> Result<bool> {
        self.metadata_store.has_version_index(object_id).await
    }

    async fn delete_version_index_by_object_id(&self, object_id: &str) -> Result<()> {
        self.metadata_store
            .delete_version_index_by_object_id(object_id)
            .await
    }

    async fn list_media_cache_fingerprints(&self) -> Result<Vec<String>> {
        self.metadata_store.list_media_cache_fingerprints().await
    }

    async fn list_archive_paths(&self) -> Result<Vec<PathBuf>> {
        let archive_dir = self.tombstone_archive_dir();
        if !fs::try_exists(&archive_dir).await? {
            return Ok(Vec::new());
        }

        let mut entries = fs::read_dir(&archive_dir).await?;
        let mut paths = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
                paths.push(path);
            }
        }
        Ok(paths)
    }

    async fn validate_archive_file(&self, file_name: &str) -> Result<PathBuf> {
        if file_name.contains('/') || file_name.contains('\\') {
            bail!("archive file name must not include path separators");
        }
        if Path::new(file_name)
            .extension()
            .and_then(|value| value.to_str())
            != Some("jsonl")
        {
            bail!("archive file must end with .jsonl");
        }

        let path = self.tombstone_archive_dir().join(file_name);
        if !fs::try_exists(&path).await? {
            bail!("archive file not found: {}", path.display());
        }
        Ok(path)
    }
}

fn empty_version_index(object_id: &str) -> FileVersionIndex {
    FileVersionIndex {
        object_id: object_id.to_string(),
        versions: HashMap::new(),
        head_version_ids: Vec::new(),
        preferred_head_version_id: None,
    }
}

fn content_fingerprint_from_manifest(manifest: &ObjectManifest) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironmesh-content-fingerprint-v1");
    hasher.update(&(manifest.total_size_bytes as u64).to_le_bytes());
    for chunk in &manifest.chunks {
        hasher.update(chunk.hash.as_bytes());
        hasher.update(&(chunk.size_bytes as u64).to_le_bytes());
    }
    format!("cfp-{}", hasher.finalize().to_hex())
}

async fn file_size_bytes(path: &Path) -> Result<u64> {
    match fs::metadata(path).await {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err).with_context(|| format!("failed to stat {}", path.display())),
    }
}

async fn directory_size_bytes(root: &Path) -> Result<u64> {
    match fs::metadata(root).await {
        Ok(metadata) if metadata.is_file() => return Ok(metadata.len()),
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to stat {}", root.display()));
        }
    }

    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = match fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", dir.display()));
            }
        };

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = entry
                .metadata()
                .await
                .with_context(|| format!("failed to stat {}", path.display()))?;
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }

    Ok(total)
}

fn derive_image_media_cache(
    manifest_hash: &str,
    content_fingerprint: &str,
    source_size_bytes: usize,
    payload: &[u8],
) -> Result<CachedMediaMetadata> {
    let generated_at_unix = unix_ts();
    let format = match image::guess_format(payload) {
        Ok(format) => format,
        Err(_) => {
            return Ok(CachedMediaMetadata {
                schema_version: MEDIA_CACHE_SCHEMA_VERSION,
                content_fingerprint: content_fingerprint.to_string(),
                source_manifest_hash: manifest_hash.to_string(),
                status: MediaCacheStatus::Unsupported,
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
                error: Some("unsupported media format".to_string()),
            });
        }
    };

    let mime_type = match image_format_mime_type(format) {
        Some(value) => value.to_string(),
        None => {
            return Ok(CachedMediaMetadata {
                schema_version: MEDIA_CACHE_SCHEMA_VERSION,
                content_fingerprint: content_fingerprint.to_string(),
                source_manifest_hash: manifest_hash.to_string(),
                status: MediaCacheStatus::Unsupported,
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
                error: Some("media format is not supported for thumbnail extraction".to_string()),
            });
        }
    };

    let image = image::load_from_memory_with_format(payload, format)
        .context("failed to decode image payload")?;
    let (width, height) = image.dimensions();
    let (orientation, gps) = extract_exif_fields(payload);
    let rendered_thumbnail = render_thumbnail(image, orientation, GRID_THUMBNAIL_MAX_DIMENSION)?;

    Ok(CachedMediaMetadata {
        schema_version: MEDIA_CACHE_SCHEMA_VERSION,
        content_fingerprint: content_fingerprint.to_string(),
        source_manifest_hash: manifest_hash.to_string(),
        status: MediaCacheStatus::Ready,
        media_type: Some("image".to_string()),
        mime_type: Some(mime_type),
        width: Some(width),
        height: Some(height),
        orientation,
        taken_at_unix: None,
        gps,
        thumbnail: Some(CachedThumbnailInfo {
            profile: GRID_THUMBNAIL_PROFILE.to_string(),
            format: "jpeg".to_string(),
            width: rendered_thumbnail.width,
            height: rendered_thumbnail.height,
            size_bytes: rendered_thumbnail.payload.len() as u64,
        }),
        source_size_bytes,
        generated_at_unix,
        error: None,
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

fn current_media_cache_metadata(
    metadata: Option<CachedMediaMetadata>,
) -> Option<CachedMediaMetadata> {
    metadata.filter(|metadata| metadata.schema_version == MEDIA_CACHE_SCHEMA_VERSION)
}

fn extract_exif_orientation(payload: &[u8]) -> Option<u16> {
    extract_exif_fields(payload).0
}

fn render_thumbnail_from_payload(
    payload: &[u8],
    orientation: Option<u16>,
    max_dimension: u32,
) -> Result<RenderedThumbnail> {
    let image = image::load_from_memory(payload)
        .context("failed to decode image while rendering thumbnail")?;
    render_thumbnail(image, orientation, max_dimension)
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

fn extract_exif_fields(payload: &[u8]) -> (Option<u16>, Option<MediaGpsCoordinates>) {
    let mut cursor = Cursor::new(payload);
    let exif = match ExifReader::new().read_from_container(&mut cursor) {
        Ok(value) => value,
        Err(_) => return (None, None),
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

    (orientation, gps)
}

fn exif_ascii_ref(field: Option<&exif::Field>) -> Option<char> {
    match &field?.value {
        Value::Ascii(values) => {
            let value = values.first()?;
            std::str::from_utf8(value).ok()?.chars().next()
        }
        _ => None,
    }
}

fn exif_gps_coordinate(value: &Value) -> Option<f64> {
    match value {
        Value::Rational(values) if values.len() >= 3 => {
            let degrees = values[0].to_f64();
            let minutes = values[1].to_f64();
            let seconds = values[2].to_f64();
            Some(degrees + (minutes / 60.0) + (seconds / 3600.0))
        }
        _ => None,
    }
}

fn generate_object_id() -> String {
    format!("obj-{}", Uuid::now_v7())
}

fn recompute_head_version_ids(index: &FileVersionIndex) -> Vec<String> {
    let mut all_ids: HashSet<String> = index.versions.keys().cloned().collect();
    for record in index.versions.values() {
        for parent in &record.parent_version_ids {
            all_ids.remove(parent);
        }
    }

    let mut heads: Vec<String> = all_ids.into_iter().collect();
    heads.sort();
    heads
}

fn choose_preferred_head(index: &FileVersionIndex) -> Option<String> {
    choose_preferred_head_with_reason(index).map(|(id, _)| id)
}

fn choose_preferred_head_with_reason(
    index: &FileVersionIndex,
) -> Option<(String, PreferredHeadReason)> {
    let mut heads: Vec<&FileVersionRecord> = index
        .head_version_ids
        .iter()
        .filter_map(|head| index.versions.get(head))
        .collect();

    if heads.is_empty() {
        return None;
    }

    heads.sort_by(|a, b| {
        rank_state(&b.state)
            .cmp(&rank_state(&a.state))
            .then_with(|| b.created_at_unix.cmp(&a.created_at_unix))
            .then_with(|| b.version_id.cmp(&a.version_id))
    });

    let top = heads.first()?;

    let tied_on_rank_and_time = heads.iter().skip(1).any(|entry| {
        rank_state(&entry.state) == rank_state(&top.state)
            && entry.created_at_unix == top.created_at_unix
    });

    let reason = if tied_on_rank_and_time {
        PreferredHeadReason::DeterministicTiebreakVersionId
    } else if top.state == VersionConsistencyState::Confirmed {
        PreferredHeadReason::ConfirmedPreferredOverProvisional
    } else {
        PreferredHeadReason::ProvisionalFallbackNoConfirmed
    };

    Some((top.version_id.clone(), reason))
}

fn manifest_hash_for_read_mode(
    index: &FileVersionIndex,
    read_mode: ObjectReadMode,
) -> Option<String> {
    version_record_for_read_mode(index, read_mode).map(|record| record.manifest_hash.clone())
}

fn version_record_for_read_mode(
    index: &FileVersionIndex,
    read_mode: ObjectReadMode,
) -> Option<&FileVersionRecord> {
    let mut heads: Vec<&FileVersionRecord> = index
        .head_version_ids
        .iter()
        .filter_map(|head| index.versions.get(head))
        .collect();

    if heads.is_empty() {
        return None;
    }

    match read_mode {
        ObjectReadMode::Preferred => {
            let preferred = choose_preferred_head(index)?;
            index.versions.get(&preferred)
        }
        ObjectReadMode::ConfirmedOnly => {
            heads.retain(|record| record.state == VersionConsistencyState::Confirmed);

            heads.sort_by(|a, b| {
                b.created_at_unix
                    .cmp(&a.created_at_unix)
                    .then_with(|| b.version_id.cmp(&a.version_id))
            });

            heads.first().copied()
        }
        ObjectReadMode::ProvisionalAllowed => {
            heads.sort_by(|a, b| {
                b.created_at_unix
                    .cmp(&a.created_at_unix)
                    .then_with(|| b.version_id.cmp(&a.version_id))
            });

            heads.first().copied()
        }
    }
}

fn rank_state(state: &VersionConsistencyState) -> u8 {
    match state {
        VersionConsistencyState::Confirmed => 2,
        VersionConsistencyState::Provisional => 1,
    }
}

fn chunk_path_for_hash(chunks_dir: &Path, hash: &str) -> PathBuf {
    let prefix = &hash[..2.min(hash.len())];
    chunks_dir.join(prefix).join(hash)
}

fn hash_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_ts_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

async fn write_atomic(path: &Path, payload: &[u8]) -> Result<()> {
    let total_started_at = Instant::now();
    let parent = path
        .parent()
        .with_context(|| format!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).await?;

    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let write_started_at = Instant::now();
    fs::write(&tmp, payload).await?;
    let write_ms = write_started_at.elapsed().as_millis();
    let rename_started_at = Instant::now();
    fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed to move {} -> {}", tmp.display(), path.display()))?;
    let rename_ms = rename_started_at.elapsed().as_millis();

    let total_ms = total_started_at.elapsed().as_millis();
    if total_ms >= SLOW_STORAGE_WRITE_LOG_THRESHOLD_MS {
        info!(
            path = %path.display(),
            size_bytes = payload.len(),
            write_ms,
            rename_ms,
            total_ms,
            "slow atomic file write"
        );
    }

    Ok(())
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
