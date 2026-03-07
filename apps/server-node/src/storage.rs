use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
use common::NodeId;
use exif::{In, Reader as ExifReader, Tag, Value};
use image::codecs::jpeg::JpegEncoder;
use image::{GenericImageView, ImageFormat};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const CHUNK_SIZE: usize = 1024 * 1024;
const TOMBSTONE_MANIFEST_HASH: &str = "__tombstone__";
const MEDIA_CACHE_SCHEMA_VERSION: u32 = 1;
const GRID_THUMBNAIL_MAX_DIMENSION: u32 = 256;
const GRID_THUMBNAIL_PROFILE: &str = "grid";

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

#[derive(Debug, Clone, Serialize)]
pub struct CleanupReport {
    pub retention_secs: u64,
    pub dry_run: bool,
    pub protected_manifests: usize,
    pub protected_chunks: usize,
    pub skipped_recent_manifests: usize,
    pub skipped_recent_chunks: usize,
    pub deleted_manifests: usize,
    pub deleted_chunks: usize,
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
    pub state: VersionConsistencyState,
    pub manifest_hash: String,
    pub manifest_bytes: Vec<u8>,
    pub manifest: ReplicationManifestPayload,
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

pub struct PersistentStore {
    root_dir: PathBuf,
    chunks_dir: PathBuf,
    manifests_dir: PathBuf,
    snapshots_dir: PathBuf,
    versions_dir: PathBuf,
    reconcile_markers_dir: PathBuf,
    current_state_path: PathBuf,
    repair_attempts_path: PathBuf,
    cluster_replicas_path: PathBuf,
    admin_audit_log_path: PathBuf,
    media_metadata_dir: PathBuf,
    media_thumbnails_dir: PathBuf,
    current_state: CurrentState,
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

impl PersistentStore {
    pub async fn init(root_dir: impl Into<PathBuf>) -> Result<Self> {
        let root_dir = root_dir.into();
        let chunks_dir = root_dir.join("chunks");
        let manifests_dir = root_dir.join("manifests");
        let snapshots_dir = root_dir.join("snapshots");
        let versions_dir = root_dir.join("versions");
        let reconcile_markers_dir = root_dir.join("reconcile_markers");
        let state_dir = root_dir.join("state");
        let current_state_path = state_dir.join("current.json");
        let repair_attempts_path = state_dir.join("repair_attempts.json");
        let cluster_replicas_path = state_dir.join("cluster_replicas.json");
        let admin_audit_log_path = state_dir.join("admin_audit.jsonl");
        let media_cache_dir = state_dir.join("media_cache");
        let media_metadata_dir = media_cache_dir.join("metadata");
        let media_thumbnails_dir = media_cache_dir.join("thumbnails");

        fs::create_dir_all(&chunks_dir).await?;
        fs::create_dir_all(&manifests_dir).await?;
        fs::create_dir_all(&snapshots_dir).await?;
        fs::create_dir_all(&versions_dir).await?;
        fs::create_dir_all(&reconcile_markers_dir).await?;
        fs::create_dir_all(&state_dir).await?;
        fs::create_dir_all(&media_metadata_dir).await?;
        fs::create_dir_all(&media_thumbnails_dir).await?;

        let current_state = if fs::try_exists(&current_state_path).await? {
            let payload = fs::read(&current_state_path).await?;
            serde_json::from_slice::<CurrentState>(&payload).with_context(|| {
                format!("invalid current state: {}", current_state_path.display())
            })?
        } else {
            CurrentState::default()
        };

        Ok(Self {
            root_dir,
            chunks_dir,
            manifests_dir,
            snapshots_dir,
            versions_dir,
            reconcile_markers_dir,
            current_state_path,
            repair_attempts_path,
            cluster_replicas_path,
            admin_audit_log_path,
            media_metadata_dir,
            media_thumbnails_dir,
            current_state,
        })
    }

    pub async fn load_repair_attempts(&self) -> Result<HashMap<String, RepairAttemptRecord>> {
        if !fs::try_exists(&self.repair_attempts_path).await? {
            return Ok(HashMap::new());
        }

        let payload = fs::read(&self.repair_attempts_path).await?;
        let attempts = serde_json::from_slice::<HashMap<String, RepairAttemptRecord>>(&payload)
            .with_context(|| {
                format!(
                    "invalid repair attempts state: {}",
                    self.repair_attempts_path.display()
                )
            })?;

        Ok(attempts)
    }

    pub async fn persist_repair_attempts(
        &self,
        attempts: &HashMap<String, RepairAttemptRecord>,
    ) -> Result<()> {
        let payload = serde_json::to_vec_pretty(attempts)?;
        write_atomic(&self.repair_attempts_path, &payload).await
    }

    pub async fn load_cluster_replicas(&self) -> Result<HashMap<String, Vec<NodeId>>> {
        if !fs::try_exists(&self.cluster_replicas_path).await? {
            return Ok(HashMap::new());
        }

        let payload = fs::read(&self.cluster_replicas_path).await?;
        let replicas = serde_json::from_slice::<HashMap<String, Vec<NodeId>>>(&payload)
            .with_context(|| {
                format!(
                    "invalid cluster replicas state: {}",
                    self.cluster_replicas_path.display()
                )
            })?;

        Ok(replicas)
    }

    pub async fn persist_cluster_replicas(
        &self,
        replicas: &HashMap<String, Vec<NodeId>>,
    ) -> Result<()> {
        let payload = serde_json::to_vec_pretty(replicas)?;
        write_atomic(&self.cluster_replicas_path, &payload).await
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn object_count(&self) -> usize {
        self.current_state.objects.len()
    }

    pub fn current_keys(&self) -> Vec<String> {
        self.current_state.objects.keys().cloned().collect()
    }

    pub fn current_object_hashes(&self) -> HashMap<String, String> {
        self.current_state.objects.clone()
    }

    pub async fn snapshot_object_hashes(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<HashMap<String, String>>> {
        Ok(self
            .load_snapshot_manifest(snapshot_id)
            .await?
            .map(|manifest| manifest.objects))
    }

    async fn load_snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
        let snapshot_path = self.snapshots_dir.join(format!("{snapshot_id}.json"));
        if !fs::try_exists(&snapshot_path).await? {
            return Ok(None);
        }

        let payload = fs::read(&snapshot_path).await?;
        let manifest = serde_json::from_slice::<SnapshotManifest>(&payload)
            .with_context(|| format!("invalid snapshot manifest {}", snapshot_path.display()))?;
        Ok(Some(manifest))
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

    pub async fn lookup_media_cache(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<MediaCacheLookup>> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
            return Ok(None);
        };
        let content_fingerprint = content_fingerprint_from_manifest(&manifest);
        let metadata = self
            .load_cached_media_metadata(&content_fingerprint)
            .await?;

        Ok(Some(MediaCacheLookup {
            content_fingerprint,
            metadata,
        }))
    }

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
        if let Some(existing) = self
            .load_cached_media_metadata(&content_fingerprint)
            .await?
        {
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

    pub async fn list_replication_subjects(&self) -> Result<Vec<String>> {
        let mut subjects: HashSet<String> = self.current_state.objects.keys().cloned().collect();
        for (path, object_id) in &self.current_state.object_ids {
            if let Some(index) = self.load_version_index_by_object_id(object_id).await? {
                for head_version_id in &index.head_version_ids {
                    subjects.insert(format!("{path}@{head_version_id}"));
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

        if !fs::try_exists(&manifest_path).await? {
            write_atomic(&manifest_path, &manifest_bytes).await?;
        }

        self.finalize_put_from_manifest_hash(key, &manifest_hash, options, 0, 0)
            .await
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
        let object_id = self.object_id_for_key(key);
        let (selected_version_id, state, manifest_hash) = if let Some(version_id) = version_id {
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
                record.state.clone(),
                record.manifest_hash.clone(),
            )
        } else {
            match object_id {
                Some(object_id) => match self.load_version_index_by_object_id(&object_id).await? {
                    Some(index) => {
                        let Some(record) = version_record_for_read_mode(&index, read_mode) else {
                            return Ok(None);
                        };

                        (
                            Some(record.version_id.clone()),
                            record.state.clone(),
                            record.manifest_hash.clone(),
                        )
                    }
                    None => {
                        let Some(manifest_hash) = self.current_state.objects.get(key).cloned()
                        else {
                            return Ok(None);
                        };
                        (None, VersionConsistencyState::Confirmed, manifest_hash)
                    }
                },
                None => {
                    let Some(manifest_hash) = self.current_state.objects.get(key).cloned() else {
                        return Ok(None);
                    };
                    (None, VersionConsistencyState::Confirmed, manifest_hash)
                }
            }
        };

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

    pub async fn read_chunk_payload(&self, hash: &str) -> Result<Option<Bytes>> {
        let chunk_path = chunk_path_for_hash(&self.chunks_dir, hash);
        if !fs::try_exists(&chunk_path).await? {
            return Ok(None);
        }

        let payload = fs::read(&chunk_path).await?;
        Ok(Some(Bytes::from(payload)))
    }

    pub async fn ingest_chunk(&self, hash: &str, payload: &[u8]) -> Result<bool> {
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
        Ok(true)
    }

    pub async fn ingest_chunk_auto(&self, payload: &[u8]) -> Result<(String, bool)> {
        let hash = hash_hex(payload);
        let stored = self.ingest_chunk(&hash, payload).await?;
        Ok((hash, stored))
    }

    pub async fn import_replica_manifest(
        &mut self,
        key: &str,
        version_id: Option<&str>,
        state: VersionConsistencyState,
        manifest_hash: &str,
        manifest_payload: &[u8],
    ) -> Result<String> {
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
            parent_version_ids: Vec::new(),
            state,
            created_at_unix: unix_ts(),
            copied_from_object_id: None,
            copied_from_version_id: None,
            copied_from_path: None,
        };

        index.versions.insert(resolved_version_id.clone(), record);

        let mut heads: HashSet<String> = index.head_version_ids.into_iter().collect();
        heads.insert(resolved_version_id.clone());

        index.head_version_ids = heads.into_iter().collect();
        index.head_version_ids.sort();
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;
        self.sync_current_state_for_key_from_index(key, &index)?;
        self.persist_current_state().await?;
        self.create_snapshot().await?;

        Ok(resolved_version_id)
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
        let path = self.reconcile_marker_path(source_node_id, key, source_version_id);
        fs::try_exists(path).await.map_err(Into::into)
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

        let path = self.reconcile_marker_path(source_node_id, key, source_version_id);
        let payload = serde_json::to_vec_pretty(&marker)?;
        write_atomic(&path, &payload).await
    }

    pub async fn list_provisional_versions(&self) -> Result<Vec<ReconcileVersionEntry>> {
        let mut entries = fs::read_dir(&self.versions_dir).await?;
        let mut output = Vec::new();
        let mut paths_by_object_id: HashMap<String, Vec<String>> = HashMap::new();
        for (path, object_id) in &self.current_state.object_ids {
            paths_by_object_id
                .entry(object_id.clone())
                .or_default()
                .push(path.clone());
        }

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let payload = fs::read(&path).await?;
            let index = serde_json::from_slice::<FileVersionIndex>(&payload)
                .with_context(|| format!("invalid version index {}", path.display()))?;

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
        let metadata_path = self.media_metadata_path(content_fingerprint);
        if !fs::try_exists(&metadata_path).await? {
            return Ok(None);
        }

        let payload = fs::read(&metadata_path).await?;
        let metadata = serde_json::from_slice::<CachedMediaMetadata>(&payload)
            .with_context(|| format!("invalid media metadata {}", metadata_path.display()))?;
        Ok(Some(metadata))
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

        let metadata_path = self.media_metadata_path(&metadata.content_fingerprint);
        let payload = serde_json::to_vec_pretty(metadata)?;
        write_atomic(&metadata_path, &payload).await
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
        let image = image::load_from_memory(&payload)
            .context("failed to decode image while rendering thumbnail")?;
        let thumbnail = image.thumbnail(max_dimension, max_dimension);
        let mut encoded = Vec::new();
        let mut encoder = JpegEncoder::new_with_quality(&mut encoded, 82);
        encoder
            .encode_image(&thumbnail)
            .context("failed to encode thumbnail")?;
        Ok(encoded)
    }

    pub fn media_thumbnail_path(&self, content_fingerprint: &str, profile: &str) -> PathBuf {
        self.media_thumbnails_dir
            .join(content_fingerprint)
            .join(format!("{profile}.jpg"))
    }

    fn media_metadata_path(&self, content_fingerprint: &str) -> PathBuf {
        self.media_metadata_dir
            .join(format!("{content_fingerprint}.json"))
    }

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
        let Some(manifest_hash) = self.current_state.objects.get(from_path).cloned() else {
            return Ok(PathMutationResult::SourceMissing);
        };

        if self.current_state.object_ids.contains_key(to_path) {
            if !overwrite {
                return Ok(PathMutationResult::TargetExists);
            }
            return Ok(PathMutationResult::TargetExists);
        }

        self.current_state.object_ids.remove(from_path);
        self.current_state.objects.remove(from_path);
        self.current_state
            .object_ids
            .insert(to_path.to_string(), object_id);
        self.current_state
            .objects
            .insert(to_path.to_string(), manifest_hash);

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

        let copied_object_id = generate_object_id();
        let copied_version_id = format!(
            "copy-{}-{}",
            unix_ts_nanos(),
            &source_head.manifest_hash[..12]
        );
        let copied_record = FileVersionRecord {
            version_id: copied_version_id.clone(),
            object_id: copied_object_id.clone(),
            manifest_hash: source_head.manifest_hash.clone(),
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
            .insert(to_path.to_string(), source_head.manifest_hash.clone());
        self.persist_current_state().await?;
        self.create_snapshot().await?;

        Ok(PathMutationResult::Applied)
    }

    pub async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        let mut entries = fs::read_dir(&self.snapshots_dir).await?;
        let mut snapshots = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let payload = fs::read(&path).await?;
            let manifest = serde_json::from_slice::<SnapshotManifest>(&payload)
                .with_context(|| format!("invalid snapshot manifest {}", path.display()))?;

            snapshots.push(SnapshotInfo {
                id: manifest.id,
                created_at_unix: manifest.created_at_unix,
                object_count: manifest.objects.len(),
            });
        }

        snapshots.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.created_at_unix));
        Ok(snapshots)
    }

    pub async fn cleanup_unreferenced(
        &self,
        retention_secs: u64,
        dry_run: bool,
    ) -> Result<CleanupReport> {
        let now = unix_ts();
        let referenced_manifests = self.collect_referenced_manifest_hashes().await?;
        let all_manifests = self.load_all_manifests().await?;

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
                deleted_manifests += 1;
            }
        }

        let mut protected_chunks = HashSet::<String>::new();
        let mut protected_media_fingerprints = HashSet::<String>::new();
        for manifest_hash in &retained_manifests {
            if let Some(manifest) = all_manifests.get(manifest_hash) {
                protected_media_fingerprints.insert(content_fingerprint_from_manifest(manifest));
                for chunk in &manifest.chunks {
                    protected_chunks.insert(chunk.hash.clone());
                }
            }
        }

        let mut skipped_recent_chunks = 0usize;
        let mut deleted_chunks = 0usize;

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

            fs::remove_file(&chunk_path).await?;
            deleted_chunks += 1;
        }

        if fs::try_exists(&self.media_metadata_dir).await? {
            let mut media_entries = fs::read_dir(&self.media_metadata_dir).await?;
            while let Some(entry) = media_entries.next_entry().await? {
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }

                let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
                    continue;
                };
                if protected_media_fingerprints.contains(stem) {
                    continue;
                }

                if dry_run {
                    continue;
                }

                if fs::try_exists(&path).await? {
                    fs::remove_file(&path).await?;
                }

                let thumb_dir = self.media_thumbnails_dir.join(stem);
                if fs::try_exists(&thumb_dir).await? {
                    let _ = fs::remove_dir_all(&thumb_dir).await;
                }
            }
        }

        Ok(CleanupReport {
            retention_secs,
            dry_run,
            protected_manifests: referenced_manifests.len(),
            protected_chunks: protected_chunks.len(),
            skipped_recent_manifests,
            skipped_recent_chunks,
            deleted_manifests,
            deleted_chunks,
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
        let mut eligible = Vec::<(PathBuf, String, String, u64, FileVersionIndex)>::new();

        let mut version_entries = fs::read_dir(&self.versions_dir).await?;
        while let Some(entry) = version_entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            scanned_indexes += 1;
            let payload = fs::read(&path).await?;
            let index = serde_json::from_slice::<FileVersionIndex>(&payload)
                .with_context(|| format!("invalid version index {}", path.display()))?;

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
                path,
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
        for (path, object_id, preferred_tombstone_version_id, tombstone_created_at_unix, index) in
            eligible
        {
            let record = ArchivedTombstoneIndexRecord {
                object_id,
                preferred_tombstone_version_id,
                preferred_tombstone_created_at_unix: tombstone_created_at_unix,
                archived_at_unix: now,
                index,
            };
            let mut line = serde_json::to_vec(&record)?;
            line.push(b'\n');
            archive_writer.write_all(&line).await?;
            archived_indexes += 1;

            if fs::try_exists(&path).await? {
                fs::remove_file(&path).await?;
                removed_indexes += 1;
            }
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

        let index_path = self.version_index_path(object_id);
        let index_path_string = index_path.to_string_lossy().to_string();
        let index_exists = fs::try_exists(&index_path).await?;
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

        let payload = serde_json::to_vec_pretty(&record.index)?;
        write_atomic(&index_path, &payload).await?;
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
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.admin_audit_log_path)
            .await
            .with_context(|| format!("failed to open {}", self.admin_audit_log_path.display()))?;
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        file.write_all(&line).await?;
        file.flush().await?;
        Ok(())
    }

    fn object_id_for_key(&self, key: &str) -> Option<String> {
        self.current_state.object_ids.get(key).cloned()
    }

    async fn load_version_index_by_object_id(
        &self,
        object_id: &str,
    ) -> Result<Option<FileVersionIndex>> {
        let path = self.version_index_path(object_id);

        if !fs::try_exists(&path).await? {
            return Ok(None);
        }

        let payload = fs::read(&path).await?;
        let index = serde_json::from_slice::<FileVersionIndex>(&payload)
            .with_context(|| format!("invalid version index {}", path.display()))?;

        Ok(Some(index))
    }

    async fn persist_version_index_by_object_id(
        &self,
        object_id: &str,
        index: &FileVersionIndex,
    ) -> Result<()> {
        let path = self.version_index_path(object_id);
        let payload = serde_json::to_vec_pretty(index)?;
        write_atomic(&path, &payload).await
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
        let payload = serde_json::to_vec_pretty(&self.current_state)?;
        write_atomic(&self.current_state_path, &payload).await
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

        let payload = serde_json::to_vec_pretty(&manifest)?;
        let path = self.snapshots_dir.join(format!("{snapshot_id}.json"));

        if !fs::try_exists(&path).await? {
            write_atomic(&path, &payload).await?;
        }

        Ok(snapshot_id)
    }

    async fn read_snapshot(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
        let path = self.snapshots_dir.join(format!("{snapshot_id}.json"));

        if !fs::try_exists(&path).await? {
            return Ok(None);
        }

        let payload = fs::read(&path).await?;
        let snapshot = serde_json::from_slice::<SnapshotManifest>(&payload)
            .with_context(|| format!("invalid snapshot manifest {}", path.display()))?;

        Ok(Some(snapshot))
    }

    async fn collect_referenced_manifest_hashes(&self) -> Result<HashSet<String>> {
        let mut referenced = HashSet::<String>::new();

        for manifest_hash in self.current_state.objects.values() {
            referenced.insert(manifest_hash.clone());
        }

        let mut snapshot_entries = fs::read_dir(&self.snapshots_dir).await?;
        while let Some(entry) = snapshot_entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let payload = fs::read(&path).await?;
            let snapshot = serde_json::from_slice::<SnapshotManifest>(&payload)
                .with_context(|| format!("invalid snapshot manifest {}", path.display()))?;

            for manifest_hash in snapshot.objects.values() {
                referenced.insert(manifest_hash.clone());
            }
        }

        let mut version_entries = fs::read_dir(&self.versions_dir).await?;
        while let Some(entry) = version_entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let payload = fs::read(&path).await?;
            let index = serde_json::from_slice::<FileVersionIndex>(&payload)
                .with_context(|| format!("invalid version index {}", path.display()))?;

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

    fn version_index_path(&self, object_id: &str) -> PathBuf {
        let object_id_hash = hash_hex(object_id.as_bytes());
        self.versions_dir.join(format!("{object_id_hash}.json"))
    }

    fn reconcile_marker_path(
        &self,
        source_node_id: &str,
        key: &str,
        source_version_id: &str,
    ) -> PathBuf {
        let seed = format!("{source_node_id}:{key}:{source_version_id}");
        let marker_id = hash_hex(seed.as_bytes());
        self.reconcile_markers_dir.join(format!("{marker_id}.json"))
    }

    fn tombstone_archive_dir(&self) -> PathBuf {
        self.root_dir.join("state").join("tombstone_archive")
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
    let thumbnail = image.thumbnail(GRID_THUMBNAIL_MAX_DIMENSION, GRID_THUMBNAIL_MAX_DIMENSION);
    let mut thumbnail_payload = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut thumbnail_payload, 82);
    encoder
        .encode_image(&thumbnail)
        .context("failed to encode thumbnail")?;

    let (orientation, gps) = extract_exif_fields(payload);

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
            width: thumbnail.width(),
            height: thumbnail.height(),
            size_bytes: thumbnail_payload.len() as u64,
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

    fs::write(&tmp, payload).await?;
    fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed to move {} -> {}", tmp.display(), path.display()))?;

    Ok(())
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
