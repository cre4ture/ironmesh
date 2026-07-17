use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_CURRENT_OBJECTS_CACHE_CAPACITY: usize = 100_000;

fn current_objects_cache_capacity() -> usize {
    std::env::var("IRONMESH_CURRENT_OBJECTS_CACHE_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CURRENT_OBJECTS_CACHE_CAPACITY)
}

pub(super) fn compress_snapshot_json(data: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(data, 3).context("failed to compress snapshot json")
}

pub(super) fn decompress_snapshot_json(data: &[u8]) -> Result<Vec<u8>> {
    const ZSTD_MAGIC: &[u8] = &[0x28, 0xB5, 0x2F, 0xFD];
    if data.starts_with(ZSTD_MAGIC) {
        zstd::decode_all(data).context("failed to decompress snapshot json")
    } else {
        Ok(data.to_vec())
    }
}

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use common::NodeId;
use common::content_fingerprint::content_fingerprint_from_chunk_refs;
use common::range_chunk_cache::RangeChunkCache;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

pub(super) mod data_scrub;
pub(super) mod media_cache;
pub(super) mod media_tools;
mod sqlite_impl;
#[cfg(feature = "turso-metadata")]
mod turso_impl;

use self::sqlite_impl::SqliteMetadataStore;
#[cfg(feature = "turso-metadata")]
use self::turso_impl::TursoMetadataStore;
use super::cluster::NodeDescriptor;
use super::{DataScrubRunRecord, ManualRepairActionRunRecord, RepairRunRecord};

pub use data_scrub::DataScrubReport;
pub use media_cache::{
    CachedMediaMetadata, MediaCacheLookup, MediaCacheStatus, MediaGpsCoordinates,
    media_cache_retry_due, promote_cached_media_metadata_to_incomplete,
};
pub use media_tools::{HostDependencyReport, HostDependencyStatus};

pub(crate) use data_scrub::DataScrubber;
#[cfg(test)]
pub(crate) use data_scrub::{DataScrubIssue, DataScrubIssueKind, DataScrubRunTestHook};
use media_cache::MediaCacheBuildConfig;
#[cfg(test)]
pub(crate) use media_cache::mobile_viewer_thumbnail_profile;
#[cfg(test)]
use media_cache::{
    MEDIA_CACHE_INCOMPLETE_RETRY_SECS, MEDIA_CACHE_SCHEMA_VERSION, MediaCacheImageLimits,
    exif_gps_coordinate, parse_exif_taken_at, persist_media_cache_record_with_payload,
    preferred_video_seek_time,
};
pub(crate) use media_cache::{MediaCacheWorker, current_media_cache_metadata};
pub(crate) use media_cache::{grid_thumbnail_profile, thumbnail_profile_from_query};
use media_tools::MediaToolPaths;

const CHUNK_SIZE: usize = 1024 * 1024;
pub(crate) const TOMBSTONE_MANIFEST_HASH: &str = "__tombstone__";
const SLOW_STORAGE_WRITE_LOG_THRESHOLD_MS: u128 = 100;
const SLOW_MEDIA_CACHE_LOOKUP_LOG_THRESHOLD_MS: u128 = 250;
const READ_THROUGH_CACHE_CLASS: &str = "read_through";
const LEGACY_RENAME_RECONCILE_UPDATE_SAMPLE_LIMIT: usize = 64;
const DELETE_RECREATE_LOOP_REPAIR_SAMPLE_LIMIT: usize = 64;
const SNAPSHOT_HISTORY_COMPACTION_SAMPLE_LIMIT: usize = 64;
const SNAPSHOT_HISTORY_COMPACTION_CHANGED_PATH_SAMPLE_LIMIT: usize = 8;
/// Bounds how many retained manifests `cleanup_unreferenced` loads into memory at once
/// while computing protected chunks/media fingerprints, so GC peak memory stays flat
/// as total manifest count grows.
const GC_MANIFEST_LOAD_BATCH_SIZE: usize = 500;
/// Rough per-entry cost of a resident `current_objects_cache` slot (key stored once in
/// the lookup map plus once in the LRU order queue, value holds two id/hash strings),
/// used only for the dashboard's memory-attribution estimate.
const CURRENT_OBJECT_CACHE_ENTRY_ESTIMATED_BYTES: u64 = 300;
const SNAPSHOT_HISTORY_MAX_BATCH_WINDOW_SECS: u64 = 2 * 60 * 60;

fn manifest_hash_looks_safe_filename(manifest_hash: &str) -> bool {
    manifest_hash.len() == blake3::OUT_LEN * 2
        && manifest_hash.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn manifest_path_from_hash(
    manifests_dir: &Path,
    manifest_hash: impl AsRef<str>,
) -> Result<PathBuf> {
    let manifest_hash = manifest_hash.as_ref();
    if !manifest_hash_looks_safe_filename(manifest_hash) {
        bail!("invalid manifest hash: {manifest_hash}");
    }
    Ok(manifests_dir.join(format!("{manifest_hash}.json")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ChunkRef {
    pub(super) hash: String,
    pub(super) size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ObjectManifest {
    pub(super) key: String,
    pub(super) total_size_bytes: usize,
    pub(super) chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestSummary {
    total_size_bytes: u64,
    content_fingerprint: String,
}

impl ManifestSummary {
    fn from_manifest(manifest: &ObjectManifest) -> Self {
        Self {
            total_size_bytes: manifest.total_size_bytes as u64,
            content_fingerprint: content_fingerprint_from_manifest(manifest),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotManifest {
    id: String,
    created_at_unix: u64,
    objects: HashMap<String, String>,
    #[serde(default)]
    object_ids: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveSnapshotBatch {
    snapshot_id: String,
    started_at_unix: u64,
    last_changed_at_unix: u64,
    #[serde(default)]
    dirty_paths: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct CurrentState {
    pub(super) objects: HashMap<String, String>,
    #[serde(default)]
    pub(super) object_ids: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CurrentObjectEntry {
    pub(super) manifest_hash: String,
    pub(super) object_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionConsistencyState {
    Provisional,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct FileVersionRecord {
    pub(super) version_id: String,
    pub(super) object_id: String,
    pub(super) manifest_hash: String,
    #[serde(default)]
    pub(super) logical_path: Option<String>,
    pub(super) parent_version_ids: Vec<String>,
    pub(super) state: VersionConsistencyState,
    pub(super) created_at_unix: u64,
    pub(super) copied_from_object_id: Option<String>,
    pub(super) copied_from_version_id: Option<String>,
    pub(super) copied_from_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct FileVersionIndex {
    pub(super) object_id: String,
    pub(super) versions: HashMap<String, FileVersionRecord>,
    pub(super) head_version_ids: Vec<String>,
    preferred_head_version_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionRecordSummary {
    pub version_id: String,
    #[serde(skip_serializing)]
    pub manifest_hash: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyRenameLogicalPathReconcileUpdate {
    pub object_id: String,
    pub version_id: String,
    pub manifest_hash: String,
    pub old_logical_path: String,
    pub corrected_logical_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LegacyRenameLogicalPathReconcileReport {
    pub dry_run: bool,
    pub version_indexes_scanned: usize,
    pub version_records_scanned: usize,
    pub skipped_indexes_without_rename_lineage: usize,
    pub skipped_head_records: usize,
    pub skipped_tombstone_records: usize,
    pub skipped_records_without_logical_path: usize,
    pub skipped_missing_manifests: usize,
    pub skipped_unreadable_manifests: usize,
    pub skipped_unrelated_mismatches: usize,
    pub manifest_key_mismatches_seen: usize,
    pub eligible_records: usize,
    pub updated_records: usize,
    pub sampled_updates: Vec<LegacyRenameLogicalPathReconcileUpdate>,
    pub update_sample_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteRecreateLoopCleanupGroup {
    pub key: String,
    pub kept_object_id: String,
    pub removed_object_ids: Vec<String>,
    pub preferred_head_version_id: Option<String>,
    pub version_ids: Vec<String>,
    pub manifest_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DeleteRecreateLoopCleanupReport {
    pub dry_run: bool,
    pub version_indexes_scanned: usize,
    pub eligible_single_path_indexes: usize,
    pub skipped_indexes_without_resolved_path: usize,
    pub skipped_indexes_with_multiple_paths: usize,
    pub skipped_indexes_without_delete_recreate_loop: usize,
    pub duplicate_groups: usize,
    pub duplicate_indexes: usize,
    pub removable_indexes: usize,
    pub removed_indexes: usize,
    pub sampled_groups: Vec<DeleteRecreateLoopCleanupGroup>,
    pub sampled_groups_truncated: bool,
    pub archive_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotHistoryCompactionRemovalReason {
    BatchedDistinctPaths,
    DuplicateState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotHistoryCompactionRemovedSnapshot {
    pub snapshot_id: String,
    pub created_at_unix: u64,
    pub changed_path_count: usize,
    pub sampled_changed_paths: Vec<String>,
    pub reason: SnapshotHistoryCompactionRemovalReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SnapshotHistoryCompactionReport {
    pub dry_run: bool,
    pub max_batch_window_secs: u64,
    pub snapshots_scanned: usize,
    pub snapshots_before: usize,
    pub snapshots_retained: usize,
    pub removable_snapshots: usize,
    pub removed_snapshots: usize,
    pub overlap_flush_boundaries: usize,
    pub time_window_flush_boundaries: usize,
    pub duplicate_state_snapshots: usize,
    pub vacuumed_metadata_db: bool,
    pub sampled_removed_snapshots: Vec<SnapshotHistoryCompactionRemovedSnapshot>,
    pub sampled_removed_snapshots_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompressSnapshotJsonReport {
    pub dry_run: bool,
    pub snapshots_scanned: usize,
    pub snapshots_eligible: usize,
    pub snapshots_compressed: usize,
    pub snapshots_already_compressed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArchivedDeleteRecreateLoopIndexRecord {
    key: String,
    kept_object_id: String,
    removed_object_id: String,
    archived_at_unix: u64,
    index: FileVersionIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMutationResult {
    Applied,
    SourceMissing,
    TargetExists,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRestoreReport {
    pub snapshot_id: String,
    pub source_path: String,
    pub target_path: String,
    pub recursive: bool,
    pub restored_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRestoreMutationResult {
    Applied(SnapshotRestoreReport),
    SourceMissing,
    TargetExists { path: String },
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

#[derive(Debug, Clone)]
struct SnapshotRestoreSource {
    manifest_hash: String,
    object_id: Option<String>,
    version_id: Option<String>,
    state: VersionConsistencyState,
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
    pub retained_manifests_processed: usize,
    pub peak_manifest_batch_size: usize,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CurrentObjectsCacheStats {
    pub resident_entries: usize,
    pub capacity: usize,
    pub estimated_resident_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MediaCacheClearReport {
    pub deleted_metadata_records: usize,
    pub deleted_thumbnail_files: usize,
    pub deleted_thumbnail_bytes: u64,
    pub cleared_at_unix: u64,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataChangeAction {
    Upload,
    Rename,
    Copy,
    Delete,
}

impl DataChangeAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Rename => "rename",
            Self::Copy => "copy",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataChangeActorKind {
    Client,
    Admin,
    Unknown,
}

impl DataChangeActorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Admin => "admin",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataChangeUploadMode {
    Direct,
    Chunked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataChangeEvent {
    pub event_id: String,
    pub action: DataChangeAction,
    pub path: String,
    #[serde(default)]
    pub from_path: Option<String>,
    #[serde(default)]
    pub to_path: Option<String>,
    pub recursive: bool,
    pub affected_path_count: usize,
    #[serde(default)]
    pub total_size_bytes: Option<u64>,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub upload_mode: Option<DataChangeUploadMode>,
    pub actor_kind: DataChangeActorKind,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub actor_label: Option<String>,
    #[serde(default)]
    pub actor_credential_fingerprint: Option<String>,
    #[serde(default)]
    pub actor_source_node: Option<String>,
    pub recorded_by_node_id: NodeId,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataChangeEventCursor {
    pub created_at_unix: u64,
    pub event_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct DataChangeEventQuery {
    pub limit: Option<usize>,
    pub action: Option<DataChangeAction>,
    pub path_prefix: Option<String>,
    pub actor_query: Option<String>,
    pub before: Option<DataChangeEventCursor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientCredentialState {
    #[serde(default)]
    pub pairing_authorizations: Vec<PairingAuthorizationRecord>,
    #[serde(default)]
    pub credentials: Vec<ClientCredentialRecord>,
    #[serde(default)]
    pub bootstrap_claims: Vec<ClientBootstrapClaimRecord>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientBootstrapClaimRecord {
    pub claim_id: String,
    pub claim_secret_hash: String,
    pub label: Option<String>,
    pub target_node_id: NodeId,
    #[serde(default)]
    pub rendezvous_urls: Vec<String>,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    #[serde(default)]
    pub used_at_unix: Option<u64>,
    #[serde(default)]
    pub consumed_by_device_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum S3BucketVersioningStatus {
    #[default]
    Disabled,
    Enabled,
}

impl S3BucketVersioningStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "disabled" => Some(Self::Disabled),
            "enabled" => Some(Self::Enabled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct S3BucketRecord {
    pub bucket_name: String,
    pub root_prefix: String,
    pub versioning_status: S3BucketVersioningStatus,
    pub read_only: bool,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub deleted_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct S3AccessKeyRecord {
    pub access_key_id: String,
    pub secret_material: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub bucket_scope: Vec<String>,
    #[serde(default)]
    pub prefix_scope: Vec<String>,
    pub allow_list: bool,
    pub allow_read: bool,
    pub allow_write: bool,
    pub allow_delete: bool,
    #[serde(default)]
    pub allow_manage: bool,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    #[serde(default)]
    pub last_used_at_unix: Option<u64>,
    #[serde(default)]
    pub revoked_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct S3ControlPlaneState {
    #[serde(default)]
    pub buckets: Vec<S3BucketRecord>,
    #[serde(default)]
    pub access_keys: Vec<S3AccessKeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ObjectVersionMetadataRecord {
    pub version_id: String,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content_encoding: Option<String>,
    #[serde(default)]
    pub content_language: Option<String>,
    #[serde(default)]
    pub cache_control: Option<String>,
    #[serde(default)]
    pub content_disposition: Option<String>,
    #[serde(default)]
    pub user_metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub checksum_sha256: Option<String>,
    #[serde(default)]
    pub checksum_crc32c: Option<String>,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct S3ObjectVersionRecord {
    pub bucket_name: String,
    pub ironmesh_key: String,
    pub version_id: String,
    pub etag: String,
    #[serde(default)]
    pub multipart_part_count: Option<u32>,
    pub created_at_unix: u64,
}

pub(super) fn sqlite_like_prefix_pattern(prefix: &str) -> String {
    let mut pattern = String::with_capacity(prefix.len() + 1);
    for ch in prefix.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            pattern.push('\\');
        }
        pattern.push(ch);
    }
    pattern.push('%');
    pattern
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectVersionInspection {
    pub version_id: String,
    pub manifest_hash: String,
    pub created_at_unix: u64,
    pub total_size_bytes: Option<u64>,
    pub is_delete_marker: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteObjectVersionOutcome {
    pub version_id: String,
    pub was_delete_marker: bool,
    pub current_object_exists: bool,
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
    #[serde(default)]
    pub object_id: Option<String>,
    pub version_id: Option<String>,
    #[serde(default)]
    pub logical_path: Option<String>,
    pub parent_version_ids: Vec<String>,
    pub state: VersionConsistencyState,
    #[serde(default)]
    pub created_at_unix: Option<u64>,
    #[serde(default)]
    pub copied_from_object_id: Option<String>,
    #[serde(default)]
    pub copied_from_version_id: Option<String>,
    #[serde(default)]
    pub copied_from_path: Option<String>,
    #[serde(default)]
    pub selected_is_preferred_head: bool,
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

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MetadataBackendKind {
    Sqlite,
    #[cfg(feature = "turso-metadata")]
    Turso,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataDbTableLogicalBreakdown {
    pub table: String,
    pub row_count: u64,
    pub tracked_value_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_tracked_value_bytes: Option<u64>,
    #[serde(default)]
    pub tracked_columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataDbLogicalDistribution {
    pub backend: MetadataBackendKind,
    pub generated_at_unix: u64,
    pub total_row_count: u64,
    pub total_tracked_value_bytes: u64,
    #[serde(default)]
    pub tables: Vec<MetadataDbTableLogicalBreakdown>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetadataDbLogicalProgress {
    pub total_tables: usize,
    pub completed_tables: usize,
    pub current_table: Option<String>,
}

pub(crate) type MetadataDbLogicalProgressCallback =
    Arc<dyn Fn(MetadataDbLogicalProgress) + Send + Sync>;

#[derive(Debug, Clone, Copy)]
pub(super) struct MetadataDbLogicalTableSpec {
    pub(super) table: &'static str,
    pub(super) tracked_columns: &'static [&'static str],
}

const METADATA_DB_LOGICAL_TABLE_SPECS: &[MetadataDbLogicalTableSpec] = &[
    MetadataDbLogicalTableSpec {
        table: "metadata_meta",
        tracked_columns: &["key", "value"],
    },
    MetadataDbLogicalTableSpec {
        table: "current_objects",
        tracked_columns: &["key", "manifest_hash", "object_id"],
    },
    MetadataDbLogicalTableSpec {
        table: "version_indexes",
        tracked_columns: &["object_id", "index_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "snapshots",
        tracked_columns: &["snapshot_id", "snapshot_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "snapshot_batch_state",
        tracked_columns: &["state_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "storage_stats_current",
        tracked_columns: &["sample_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "storage_stats_state",
        tracked_columns: &["state_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "storage_stats_history",
        tracked_columns: &["sample_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "repair_attempts",
        tracked_columns: &["subject"],
    },
    MetadataDbLogicalTableSpec {
        table: "repair_run_history",
        tracked_columns: &["run_id", "record_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "manual_repair_action_run_history",
        tracked_columns: &["run_id", "record_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "data_scrub_run_history",
        tracked_columns: &["run_id", "record_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "cluster_replicas",
        tracked_columns: &["subject", "node_id"],
    },
    MetadataDbLogicalTableSpec {
        table: "client_credential_state",
        tracked_columns: &["state_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "s3_buckets",
        tracked_columns: &[
            "bucket_name",
            "root_prefix",
            "versioning_status",
            "created_by",
            "deleted_at_unix",
        ],
    },
    MetadataDbLogicalTableSpec {
        table: "s3_access_keys",
        tracked_columns: &[
            "access_key_id",
            "secret_material",
            "description",
            "bucket_scope_json",
            "prefix_scope_json",
            "updated_at_unix",
        ],
    },
    MetadataDbLogicalTableSpec {
        table: "object_version_metadata",
        tracked_columns: &[
            "version_id",
            "content_type",
            "content_encoding",
            "content_language",
            "cache_control",
            "content_disposition",
            "user_metadata_json",
            "checksum_sha256",
            "checksum_crc32c",
        ],
    },
    MetadataDbLogicalTableSpec {
        table: "s3_object_versions",
        tracked_columns: &["bucket_name", "ironmesh_key", "version_id", "etag"],
    },
    MetadataDbLogicalTableSpec {
        table: "admin_audit_events",
        tracked_columns: &["event_id", "event_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "data_change_events",
        tracked_columns: &[
            "event_id",
            "action",
            "path",
            "from_path",
            "to_path",
            "actor_kind",
            "actor_id",
            "actor_label",
            "actor_credential_fingerprint",
            "event_json",
        ],
    },
    MetadataDbLogicalTableSpec {
        table: "media_cache",
        tracked_columns: &["content_fingerprint", "metadata_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "cached_chunks",
        tracked_columns: &["hash", "record_json"],
    },
    MetadataDbLogicalTableSpec {
        table: "manifest_summaries",
        tracked_columns: &["manifest_hash", "content_fingerprint"],
    },
    MetadataDbLogicalTableSpec {
        table: "locally_owned_manifests",
        tracked_columns: &["manifest_hash"],
    },
    MetadataDbLogicalTableSpec {
        table: "reconcile_markers",
        tracked_columns: &[
            "source_node_id",
            "key",
            "source_version_id",
            "local_version_id",
        ],
    },
];

pub(super) fn metadata_db_logical_table_specs() -> &'static [MetadataDbLogicalTableSpec] {
    METADATA_DB_LOGICAL_TABLE_SPECS
}

pub(crate) fn metadata_db_logical_table_count() -> usize {
    METADATA_DB_LOGICAL_TABLE_SPECS.len()
}

pub(super) fn metadata_db_logical_summary_query(spec: MetadataDbLogicalTableSpec) -> String {
    let tracked_value_expression = if spec.tracked_columns.is_empty() {
        "0".to_string()
    } else {
        spec.tracked_columns
            .iter()
            .map(|column| format!("COALESCE(LENGTH(CAST(\"{column}\" AS BLOB)), 0)"))
            .collect::<Vec<_>>()
            .join(" + ")
    };

    format!(
        "SELECT COUNT(*) AS row_count, COALESCE(SUM({tracked_value_expression}), 0) AS tracked_value_bytes FROM \"{}\"",
        spec.table
    )
}

pub struct PersistentStore {
    root_dir: PathBuf,
    chunks_dir: PathBuf,
    manifests_dir: PathBuf,
    metadata_backend_kind: MetadataBackendKind,
    metadata_db_path: PathBuf,
    media_thumbnails_dir: PathBuf,
    media_cache_build_permits: Arc<Semaphore>,
    media_cache_build_config: MediaCacheBuildConfig,
    current_objects_cache: std::sync::Mutex<RangeChunkCache<String, CurrentObjectEntry>>,
    gc_manifest_load_batch_size: usize,
    snapshot_batch: Option<ActiveSnapshotBatch>,
    metadata_store: Arc<dyn MetadataStore>,
    storage_stats_lock: Arc<AsyncMutex<()>>,
    chunk_ingestor: ChunkIngestor,
    media_tools: MediaToolPaths,
    #[cfg(test)]
    data_scrub_run_test_hook: Option<DataScrubRunTestHook>,
}

#[derive(Clone)]
pub(crate) struct ChunkIngestor {
    chunks_dir: PathBuf,
    metadata_store: Arc<dyn MetadataStore>,
    storage_stats_lock: Arc<AsyncMutex<()>>,
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
pub(crate) struct MetadataDbDistributionLoader {
    metadata_backend_kind: MetadataBackendKind,
    metadata_store: Arc<dyn MetadataStore>,
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
pub(crate) struct ClusterNodesPersister {
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
    async fn get_current_object(&self, key: &str) -> Result<Option<CurrentObjectEntry>>;
    async fn upsert_current_object(&self, key: &str, entry: &CurrentObjectEntry) -> Result<()>;
    async fn remove_current_object(&self, key: &str) -> Result<()>;
    async fn count_current_objects(&self) -> Result<usize>;
    async fn list_current_object_keys(&self) -> Result<Vec<String>>;
    async fn list_keys_for_object_id(&self, object_id: &str) -> Result<Vec<String>>;
    async fn load_repair_attempts(&self) -> Result<HashMap<String, RepairAttemptRecord>>;
    async fn persist_repair_attempts(
        &self,
        attempts: &HashMap<String, RepairAttemptRecord>,
    ) -> Result<()>;
    async fn list_repair_run_history(
        &self,
        limit: Option<usize>,
        finished_since_unix: Option<u64>,
    ) -> Result<Vec<RepairRunRecord>>;
    async fn persist_repair_run_record(&self, record: &RepairRunRecord) -> Result<()>;
    async fn prune_repair_run_history_before(&self, finished_before_unix: u64) -> Result<()>;
    async fn list_manual_repair_action_run_history(
        &self,
        limit: Option<usize>,
        finished_since_unix: Option<u64>,
    ) -> Result<Vec<ManualRepairActionRunRecord>>;
    async fn persist_manual_repair_action_run_record(
        &self,
        record: &ManualRepairActionRunRecord,
    ) -> Result<()>;
    async fn prune_manual_repair_action_run_history_before(
        &self,
        finished_before_unix: u64,
    ) -> Result<()>;
    async fn list_data_scrub_run_history(
        &self,
        limit: Option<usize>,
        finished_since_unix: Option<u64>,
    ) -> Result<Vec<DataScrubRunRecord>>;
    async fn persist_data_scrub_run_record(&self, record: &DataScrubRunRecord) -> Result<()>;
    async fn prune_data_scrub_run_history_before(&self, finished_before_unix: u64) -> Result<()>;
    async fn load_cluster_nodes(&self) -> Result<Vec<NodeDescriptor>>;
    async fn persist_cluster_nodes(&self, nodes: &[NodeDescriptor]) -> Result<()>;
    async fn load_cluster_replicas(&self) -> Result<HashMap<String, Vec<NodeId>>>;
    async fn persist_cluster_replicas(&self, replicas: &HashMap<String, Vec<NodeId>>)
    -> Result<()>;
    async fn load_client_credential_state(&self) -> Result<ClientCredentialState>;
    async fn persist_client_credential_state(&self, state: &ClientCredentialState) -> Result<()>;
    async fn load_s3_control_plane_state(&self) -> Result<S3ControlPlaneState>;
    async fn persist_s3_control_plane_state(&self, state: &S3ControlPlaneState) -> Result<()>;
    async fn load_snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>>;
    async fn load_snapshot_batch_state(&self) -> Result<Option<ActiveSnapshotBatch>>;
    async fn persist_snapshot_batch_state(&self, state: Option<&ActiveSnapshotBatch>)
    -> Result<()>;
    async fn load_cached_media_metadata(
        &self,
        content_fingerprint: &str,
    ) -> Result<Option<CachedMediaMetadata>>;
    async fn load_cached_media_metadata_many(
        &self,
        content_fingerprints: &[String],
    ) -> Result<HashMap<String, CachedMediaMetadata>>;
    async fn persist_media_cache_record(&self, metadata: &CachedMediaMetadata) -> Result<()>;
    async fn delete_media_cache_record(&self, content_fingerprint: &str) -> Result<()>;
    async fn list_snapshot_infos(&self) -> Result<Vec<SnapshotInfo>>;
    async fn list_data_change_events(
        &self,
        query: &DataChangeEventQuery,
    ) -> Result<Vec<DataChangeEvent>>;
    async fn append_admin_audit_event(&self, event: &AdminAuditEvent) -> Result<()>;
    async fn append_data_change_event(&self, event: &DataChangeEvent) -> Result<()>;
    async fn load_version_index_by_object_id(
        &self,
        object_id: &str,
    ) -> Result<Option<FileVersionIndex>>;
    async fn load_manifest_summaries(
        &self,
        manifest_hashes: &[String],
    ) -> Result<HashMap<String, ManifestSummary>>;
    async fn load_object_version_metadata(
        &self,
        version_id: &str,
    ) -> Result<Option<ObjectVersionMetadataRecord>>;
    async fn persist_object_version_metadata(
        &self,
        metadata: &ObjectVersionMetadataRecord,
    ) -> Result<()>;
    async fn delete_object_version_metadata(&self, version_id: &str) -> Result<()>;
    async fn load_s3_object_version(
        &self,
        bucket_name: &str,
        version_id: &str,
    ) -> Result<Option<S3ObjectVersionRecord>>;
    #[allow(dead_code)]
    async fn list_s3_object_versions_for_key(
        &self,
        bucket_name: &str,
        ironmesh_key: &str,
    ) -> Result<Vec<S3ObjectVersionRecord>>;
    async fn list_s3_object_versions(
        &self,
        bucket_name: &str,
        ironmesh_key_prefix: Option<&str>,
    ) -> Result<Vec<S3ObjectVersionRecord>>;
    async fn persist_s3_object_version(&self, record: &S3ObjectVersionRecord) -> Result<()>;
    async fn delete_s3_object_version(&self, bucket_name: &str, version_id: &str) -> Result<()>;
    async fn persist_manifest_summary(
        &self,
        manifest_hash: &str,
        summary: &ManifestSummary,
    ) -> Result<()>;
    async fn persist_version_index_by_object_id(
        &self,
        object_id: &str,
        index: &FileVersionIndex,
    ) -> Result<()>;
    async fn load_all_version_indexes(&self) -> Result<Vec<FileVersionIndex>>;
    async fn list_version_index_object_ids(&self) -> Result<Vec<String>>;
    async fn persist_snapshot_manifest(&self, manifest: &SnapshotManifest) -> Result<()>;
    async fn load_all_snapshots(&self) -> Result<Vec<SnapshotManifest>>;
    async fn load_snapshot_by_id(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>>;
    async fn list_uncompressed_snapshot_ids(&self) -> Result<Vec<String>>;
    async fn delete_snapshots_by_id(&self, snapshot_ids: &[String]) -> Result<()>;
    async fn vacuum_metadata_store(&self) -> Result<bool>;
    async fn load_storage_stats_state(&self) -> Result<Option<StorageStatsState>>;
    async fn persist_storage_stats_state(&self, state: &StorageStatsState) -> Result<()>;
    async fn load_cached_chunk_record(&self, hash: &str) -> Result<Option<CachedChunkRecord>>;
    async fn persist_cached_chunk_record(&self, record: &CachedChunkRecord) -> Result<()>;
    async fn delete_cached_chunk_record(&self, hash: &str) -> Result<()>;
    async fn list_cached_chunk_records(&self) -> Result<Vec<CachedChunkRecord>>;
    #[cfg(test)]
    async fn has_media_cache_record(&self, content_fingerprint: &str) -> Result<bool>;
    async fn mark_manifest_locally_owned(
        &self,
        manifest_hash: &str,
        owned_at_unix: u64,
    ) -> Result<()>;
    async fn delete_locally_owned_manifest(&self, manifest_hash: &str) -> Result<()>;
    async fn list_locally_owned_manifests(&self) -> Result<Vec<String>>;
    async fn filter_locally_owned_manifests(
        &self,
        manifest_hashes: &[String],
    ) -> Result<HashSet<String>> {
        if manifest_hashes.is_empty() {
            return Ok(HashSet::new());
        }

        let locally_owned = self.list_locally_owned_manifests().await?;
        let requested = manifest_hashes
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        Ok(locally_owned
            .into_iter()
            .filter(|manifest_hash| requested.contains(manifest_hash.as_str()))
            .collect())
    }
    async fn load_current_storage_stats(&self) -> Result<Option<StorageStatsSample>>;
    async fn list_storage_stats_history(
        &self,
        limit: Option<usize>,
        collected_since_unix: Option<u64>,
    ) -> Result<Vec<StorageStatsSample>>;
    async fn load_metadata_db_logical_breakdown(
        &self,
        progress: Option<MetadataDbLogicalProgressCallback>,
    ) -> Result<Vec<MetadataDbTableLogicalBreakdown>>;
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

        let chunk_path = chunk_path_for_hash(&self.chunks_dir, hash)?;
        let mut replaced_existing_path = false;
        if fs::try_exists(&chunk_path).await? {
            match fs::read(&chunk_path).await {
                Ok(existing_payload) if hash_hex(&existing_payload) == hash => {
                    return Ok(false);
                }
                Ok(_) | Err(_) => {
                    replaced_existing_path = true;
                }
            }
        }

        if let Some(parent) = chunk_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        write_atomic_overwrite(&chunk_path, payload).await?;
        if replaced_existing_path {
            self.reconcile_chunk_store_bytes_state().await?;
        } else {
            self.note_chunk_store_delta(payload.len() as i64).await?;
        }
        Ok(true)
    }

    pub(crate) async fn ingest_chunk_auto(&self, payload: &[u8]) -> Result<(String, bool)> {
        let hash = hash_hex(payload);
        let stored = self.ingest_chunk(&hash, payload).await?;
        Ok((hash, stored))
    }

    pub(crate) async fn available_upload_chunk_refs(
        &self,
        chunk_refs: &[UploadChunkRef],
    ) -> Result<Vec<Option<UploadChunkRef>>> {
        let mut available = Vec::with_capacity(chunk_refs.len());
        for chunk_ref in chunk_refs {
            let entry = match validate_local_chunk_integrity(
                &self.chunks_dir,
                &chunk_ref.hash,
                chunk_ref.size_bytes,
            )
            .await?
            {
                LocalChunkIntegrity::Valid => Some(chunk_ref.clone()),
                LocalChunkIntegrity::Missing
                | LocalChunkIntegrity::SizeMismatch { .. }
                | LocalChunkIntegrity::HashMismatch { .. } => None,
            };
            available.push(entry);
        }
        Ok(available)
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
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash)?;
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
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash)?;
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

    pub(crate) async fn object_sizes_and_content_fingerprints_by_key(
        &self,
        object_hashes: &HashMap<String, String>,
    ) -> Result<(HashMap<String, u64>, HashMap<String, String>)> {
        let mut sizes = HashMap::with_capacity(object_hashes.len());
        let mut content_fingerprints = HashMap::with_capacity(object_hashes.len());
        let requested_manifest_hashes = object_hashes
            .values()
            .filter(|manifest_hash| manifest_hash.as_str() != TOMBSTONE_MANIFEST_HASH)
            .cloned()
            .collect::<Vec<_>>();
        let persisted_summaries = match self
            .metadata_store
            .load_manifest_summaries(&requested_manifest_hashes)
            .await
        {
            Ok(summaries) => summaries,
            Err(err) => {
                warn!(
                    error = %err,
                    manifest_count = requested_manifest_hashes.len(),
                    "failed loading manifest summaries for store index"
                );
                HashMap::new()
            }
        };

        for (key, manifest_hash) in object_hashes {
            if let Some(summary) = persisted_summaries.get(manifest_hash) {
                sizes.insert(key.clone(), summary.total_size_bytes);
                content_fingerprints.insert(key.clone(), summary.content_fingerprint.clone());
                continue;
            }
            if manifest_hash == TOMBSTONE_MANIFEST_HASH {
                continue;
            }

            match self.load_manifest_by_hash(manifest_hash).await {
                Ok(Some(manifest)) => {
                    let summary = ManifestSummary::from_manifest(&manifest);
                    sizes.insert(key.clone(), summary.total_size_bytes);
                    content_fingerprints.insert(key.clone(), summary.content_fingerprint.clone());
                    if let Err(err) = self
                        .metadata_store
                        .persist_manifest_summary(manifest_hash, &summary)
                        .await
                    {
                        warn!(
                            key = %key,
                            manifest_hash = %manifest_hash,
                            error = %err,
                            "failed to backfill manifest summary for store index"
                        );
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(
                        key = %key,
                        manifest_hash = %manifest_hash,
                        error = %err,
                        "skipping store index metadata for unreadable manifest"
                    );
                }
            }
        }
        Ok((sizes, content_fingerprints))
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

    pub(crate) async fn lookup_media_cache_many_by_content_fingerprint(
        &self,
        content_fingerprints: &[String],
    ) -> Result<HashMap<String, MediaCacheLookup>> {
        let unique_content_fingerprints = content_fingerprints
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if unique_content_fingerprints.is_empty() {
            return Ok(HashMap::new());
        }

        let lookup_started_at = Instant::now();
        let metadata_by_content_fingerprint = self
            .metadata_store
            .load_cached_media_metadata_many(&unique_content_fingerprints)
            .await?;
        let total_ms = lookup_started_at.elapsed().as_millis();

        let mut lookups = HashMap::with_capacity(unique_content_fingerprints.len());
        let mut metadata_present = 0usize;
        for content_fingerprint in unique_content_fingerprints {
            let metadata = current_media_cache_metadata(
                metadata_by_content_fingerprint
                    .get(&content_fingerprint)
                    .cloned(),
            );
            if metadata.is_some() {
                metadata_present += 1;
            }
            lookups.insert(
                content_fingerprint.clone(),
                MediaCacheLookup {
                    content_fingerprint,
                    metadata,
                },
            );
        }

        if total_ms >= SLOW_MEDIA_CACHE_LOOKUP_LOG_THRESHOLD_MS {
            warn!(
                requested = lookups.len(),
                metadata_present,
                total_ms,
                "slow batched media cache lookup by content fingerprint"
            );
        }

        Ok(lookups)
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

impl ClusterNodesPersister {
    fn new(metadata_store: Arc<dyn MetadataStore>) -> Self {
        Self { metadata_store }
    }

    pub(crate) async fn persist_cluster_nodes(&self, nodes: &[NodeDescriptor]) -> Result<()> {
        self.metadata_store.persist_cluster_nodes(nodes).await
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

            for head_version_id in &index.head_version_ids {
                let Some(record) = index.versions.get(head_version_id) else {
                    continue;
                };
                let Some(key) = self.resolve_key_for_version_record(&index, record).await? else {
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

        let manifest = match self.load_manifest_by_hash(manifest_hash).await {
            Ok(Some(manifest)) => manifest,
            Ok(None) => return Ok(false),
            Err(err) => {
                // A single corrupt/unreadable manifest must not abort availability
                // checks for every other object on this node: treat it as not
                // locally available (so it gets queued for repair) and keep going
                // rather than propagating the error out of the whole scan.
                warn!(
                    manifest_hash = %manifest_hash,
                    error = %err,
                    "manifest unreadable or invalid; treating as not locally available"
                );
                return Ok(false);
            }
        };

        for chunk in &manifest.chunks {
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash)?;
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
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash)?;
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

            match self.load_manifest_by_hash(&record.manifest_hash).await {
                Ok(Some(manifest)) => return Ok(Some(manifest.key)),
                Ok(None) => continue,
                Err(err) => {
                    warn!(
                        manifest_hash = %record.manifest_hash,
                        object_id = %index.object_id,
                        version_id = %record.version_id,
                        error = %err,
                        "manifest unreadable or invalid while resolving replication subject key; skipping record"
                    );
                }
            }
        }

        Ok(None)
    }

    async fn resolve_key_for_version_record(
        &self,
        index: &FileVersionIndex,
        record: &FileVersionRecord,
    ) -> Result<Option<String>> {
        if let Some(logical_path) = record.logical_path.clone() {
            return Ok(Some(logical_path));
        }

        if record.manifest_hash != TOMBSTONE_MANIFEST_HASH {
            match self.load_manifest_by_hash(&record.manifest_hash).await {
                Ok(Some(manifest)) => return Ok(Some(manifest.key)),
                Ok(None) => {}
                Err(err) => {
                    warn!(
                        manifest_hash = %record.manifest_hash,
                        object_id = %index.object_id,
                        version_id = %record.version_id,
                        error = %err,
                        "manifest unreadable or invalid while resolving replication subject key; falling back to index lookup"
                    );
                }
            }
        }

        self.resolve_key_for_version_index(index).await
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
                Arc::new(SqliteMetadataStore::open(&state_dir.join("metadata.sqlite")).await?),
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
        let current_objects_cache =
            std::sync::Mutex::new(RangeChunkCache::new(current_objects_cache_capacity()));
        let snapshot_batch = metadata_store.load_snapshot_batch_state().await?;
        let storage_stats_lock = Arc::new(AsyncMutex::new(()));
        let media_cache_build_config = MediaCacheBuildConfig::default();
        let media_cache_build_permits = Arc::new(Semaphore::new(
            media_cache_build_config.total_permits as usize,
        ));
        let chunk_ingestor = ChunkIngestor::new(
            chunks_dir.clone(),
            metadata_store.clone(),
            storage_stats_lock.clone(),
        );

        Ok(Self {
            root_dir,
            chunks_dir,
            manifests_dir,
            metadata_backend_kind: backend,
            metadata_db_path,
            media_thumbnails_dir,
            media_cache_build_permits,
            media_cache_build_config,
            current_objects_cache,
            gc_manifest_load_batch_size: GC_MANIFEST_LOAD_BATCH_SIZE,
            snapshot_batch,
            metadata_store,
            storage_stats_lock,
            chunk_ingestor,
            media_tools: MediaToolPaths::default(),
            #[cfg(test)]
            data_scrub_run_test_hook: None,
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
            self.media_cache_build_permits.clone(),
            self.media_cache_build_config.clone(),
            self.metadata_store.clone(),
            self.media_tools.clone(),
        )
    }

    pub(crate) fn host_dependency_report(&self) -> HostDependencyReport {
        self.media_tools.host_dependency_report()
    }

    #[cfg(all(test, unix))]
    pub fn set_media_tool_paths_for_test(
        &mut self,
        ffprobe: impl Into<PathBuf>,
        ffmpeg: impl Into<PathBuf>,
    ) {
        self.media_tools = MediaToolPaths {
            ffprobe: ffprobe.into(),
            ffmpeg: ffmpeg.into(),
        };
    }

    #[cfg(test)]
    pub fn set_data_scrub_run_test_hook(&mut self, hook: Option<DataScrubRunTestHook>) {
        self.data_scrub_run_test_hook = hook;
    }

    #[cfg(test)]
    pub fn set_current_objects_cache_capacity_for_test(&mut self, capacity: usize) {
        self.current_objects_cache = std::sync::Mutex::new(RangeChunkCache::new(capacity));
    }

    #[cfg(test)]
    pub fn set_media_cache_image_limits_for_test(
        &mut self,
        max_dimension: u32,
        max_pixels: u64,
        max_decode_bytes: u64,
    ) {
        self.media_cache_build_config = self
            .media_cache_build_config
            .clone()
            .with_image_limits_for_test(MediaCacheImageLimits {
                max_dimension,
                max_pixels,
                max_decode_bytes,
            });
    }

    #[cfg(test)]
    pub fn set_gc_manifest_load_batch_size_for_test(&mut self, batch_size: usize) {
        self.gc_manifest_load_batch_size = batch_size;
    }

    pub(crate) async fn store_index_inspector(&self) -> Result<StoreIndexInspector> {
        Ok(StoreIndexInspector::new(
            self.metadata_store.load_current_state().await?,
            self.manifests_dir.clone(),
            self.metadata_store.clone(),
        ))
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

    pub(crate) fn metadata_db_distribution_loader(&self) -> MetadataDbDistributionLoader {
        MetadataDbDistributionLoader {
            metadata_backend_kind: self.metadata_backend_kind,
            metadata_store: self.metadata_store.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) async fn load_metadata_db_logical_distribution(
        &self,
    ) -> Result<MetadataDbLogicalDistribution> {
        self.metadata_db_distribution_loader()
            .load_with_progress(None)
            .await
    }

    pub(crate) async fn data_scrubber(&self) -> Result<DataScrubber> {
        let scrubber = DataScrubber::new(
            self.metadata_store.load_current_state().await?,
            self.manifests_dir.clone(),
            self.chunks_dir.clone(),
            self.metadata_store.clone(),
        );
        #[cfg(test)]
        let scrubber = scrubber.with_run_test_hook(self.data_scrub_run_test_hook.clone());
        Ok(scrubber)
    }

    pub(crate) fn cluster_replicas_persister(&self) -> ClusterReplicasPersister {
        ClusterReplicasPersister::new(self.metadata_store.clone())
    }

    pub(crate) fn cluster_nodes_persister(&self) -> ClusterNodesPersister {
        ClusterNodesPersister::new(self.metadata_store.clone())
    }

    pub(crate) async fn replication_subject_inspector(
        &self,
    ) -> Result<ReplicationSubjectInspector> {
        Ok(ReplicationSubjectInspector::new(
            self.metadata_store.load_current_state().await?,
            self.manifests_dir.clone(),
            self.chunks_dir.clone(),
            self.metadata_store.clone(),
        ))
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

    pub async fn list_repair_run_history(
        &self,
        limit: Option<usize>,
        finished_since_unix: Option<u64>,
    ) -> Result<Vec<RepairRunRecord>> {
        self.metadata_store
            .list_repair_run_history(limit, finished_since_unix)
            .await
    }

    pub async fn persist_repair_run_record(&self, record: &RepairRunRecord) -> Result<()> {
        self.metadata_store.persist_repair_run_record(record).await
    }

    pub async fn prune_repair_run_history_before(&self, finished_before_unix: u64) -> Result<()> {
        self.metadata_store
            .prune_repair_run_history_before(finished_before_unix)
            .await
    }

    pub async fn list_manual_repair_action_run_history(
        &self,
        limit: Option<usize>,
        finished_since_unix: Option<u64>,
    ) -> Result<Vec<ManualRepairActionRunRecord>> {
        self.metadata_store
            .list_manual_repair_action_run_history(limit, finished_since_unix)
            .await
    }

    pub async fn persist_manual_repair_action_run_record(
        &self,
        record: &ManualRepairActionRunRecord,
    ) -> Result<()> {
        self.metadata_store
            .persist_manual_repair_action_run_record(record)
            .await
    }

    pub async fn prune_manual_repair_action_run_history_before(
        &self,
        finished_before_unix: u64,
    ) -> Result<()> {
        self.metadata_store
            .prune_manual_repair_action_run_history_before(finished_before_unix)
            .await
    }

    pub async fn list_data_scrub_run_history(
        &self,
        limit: Option<usize>,
        finished_since_unix: Option<u64>,
    ) -> Result<Vec<DataScrubRunRecord>> {
        self.metadata_store
            .list_data_scrub_run_history(limit, finished_since_unix)
            .await
    }

    pub async fn list_data_change_events(
        &self,
        query: &DataChangeEventQuery,
    ) -> Result<Vec<DataChangeEvent>> {
        self.metadata_store.list_data_change_events(query).await
    }

    pub async fn persist_data_scrub_run_record(&self, record: &DataScrubRunRecord) -> Result<()> {
        self.metadata_store
            .persist_data_scrub_run_record(record)
            .await
    }

    pub async fn prune_data_scrub_run_history_before(
        &self,
        finished_before_unix: u64,
    ) -> Result<()> {
        self.metadata_store
            .prune_data_scrub_run_history_before(finished_before_unix)
            .await
    }

    #[cfg(test)]
    pub async fn run_data_scrub(&self) -> Result<DataScrubReport> {
        self.data_scrubber().await?.run().await
    }

    pub async fn load_cluster_replicas(&self) -> Result<HashMap<String, Vec<NodeId>>> {
        self.metadata_store.load_cluster_replicas().await
    }

    pub async fn load_cluster_nodes(&self) -> Result<Vec<NodeDescriptor>> {
        self.metadata_store.load_cluster_nodes().await
    }

    #[cfg(test)]
    pub async fn persist_cluster_nodes(&self, nodes: &[NodeDescriptor]) -> Result<()> {
        self.metadata_store.persist_cluster_nodes(nodes).await
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

    pub async fn load_s3_control_plane_state(&self) -> Result<S3ControlPlaneState> {
        self.metadata_store.load_s3_control_plane_state().await
    }

    pub async fn persist_s3_control_plane_state(&self, state: &S3ControlPlaneState) -> Result<()> {
        self.metadata_store
            .persist_s3_control_plane_state(state)
            .await
    }

    pub async fn load_object_version_metadata(
        &self,
        version_id: &str,
    ) -> Result<Option<ObjectVersionMetadataRecord>> {
        self.metadata_store
            .load_object_version_metadata(version_id)
            .await
    }

    pub async fn persist_object_version_metadata(
        &self,
        metadata: &ObjectVersionMetadataRecord,
    ) -> Result<()> {
        self.metadata_store
            .persist_object_version_metadata(metadata)
            .await
    }

    pub async fn delete_object_version_metadata(&self, version_id: &str) -> Result<()> {
        self.metadata_store
            .delete_object_version_metadata(version_id)
            .await
    }

    pub async fn load_s3_object_version(
        &self,
        bucket_name: &str,
        version_id: &str,
    ) -> Result<Option<S3ObjectVersionRecord>> {
        self.metadata_store
            .load_s3_object_version(bucket_name, version_id)
            .await
    }

    #[allow(dead_code)]
    pub async fn list_s3_object_versions_for_key(
        &self,
        bucket_name: &str,
        ironmesh_key: &str,
    ) -> Result<Vec<S3ObjectVersionRecord>> {
        self.metadata_store
            .list_s3_object_versions_for_key(bucket_name, ironmesh_key)
            .await
    }

    pub async fn list_s3_object_versions(
        &self,
        bucket_name: &str,
        ironmesh_key_prefix: Option<&str>,
    ) -> Result<Vec<S3ObjectVersionRecord>> {
        self.metadata_store
            .list_s3_object_versions(bucket_name, ironmesh_key_prefix)
            .await
    }

    pub async fn persist_s3_object_version(&self, record: &S3ObjectVersionRecord) -> Result<()> {
        self.metadata_store.persist_s3_object_version(record).await
    }

    pub async fn delete_s3_object_version(
        &self,
        bucket_name: &str,
        version_id: &str,
    ) -> Result<()> {
        self.metadata_store
            .delete_s3_object_version(bucket_name, version_id)
            .await
    }

    pub async fn inspect_object_version(
        &self,
        key: &str,
        version_id: &str,
    ) -> Result<Option<ObjectVersionInspection>> {
        let Some(object_id) = self
            .resolve_object_id_for_key_version(key, version_id)
            .await?
        else {
            return Ok(None);
        };
        let Some(index) = self.load_version_index_by_object_id(&object_id).await? else {
            return Ok(None);
        };
        let Some(record) = index.versions.get(version_id) else {
            return Ok(None);
        };
        if record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(Some(ObjectVersionInspection {
                version_id: record.version_id.clone(),
                manifest_hash: record.manifest_hash.clone(),
                created_at_unix: record.created_at_unix,
                total_size_bytes: None,
                is_delete_marker: true,
            }));
        }

        let Some(manifest) = self.load_manifest_by_hash(&record.manifest_hash).await? else {
            bail!(
                "manifest missing for key={key} version_id={} hash={}",
                record.version_id,
                record.manifest_hash
            );
        };

        Ok(Some(ObjectVersionInspection {
            version_id: record.version_id.clone(),
            manifest_hash: record.manifest_hash.clone(),
            created_at_unix: record.created_at_unix,
            total_size_bytes: Some(manifest.total_size_bytes as u64),
            is_delete_marker: false,
        }))
    }

    pub async fn delete_object_version_for_key(
        &mut self,
        key: &str,
        version_id: &str,
    ) -> Result<Option<DeleteObjectVersionOutcome>> {
        let Some(object_id) = self
            .resolve_object_id_for_key_version(key, version_id)
            .await?
        else {
            return Ok(None);
        };
        let Some(mut index) = self.load_version_index_by_object_id(&object_id).await? else {
            return Ok(None);
        };
        let Some(record) = index.versions.get(version_id).cloned() else {
            return Ok(None);
        };

        let touched_paths = BTreeSet::from([key.to_string()]);
        let before_binding = self.current_state_binding(key).await?;
        self.maybe_rotate_snapshot_batch(&touched_paths).await?;

        index.versions.remove(version_id);
        if index.versions.is_empty() {
            self.delete_version_index_by_object_id(&object_id).await?;
            if self.object_id_for_key(key).await?.as_deref() == Some(object_id.as_str()) {
                self.remove_current_object(key).await?;
            }
        } else {
            index.head_version_ids = recompute_head_version_ids(&index);
            index.preferred_head_version_id = choose_preferred_head(&index);
            self.persist_version_index_by_object_id(&object_id, &index)
                .await?;
            self.sync_current_state_for_key_from_index(key, &index)
                .await?;
        }

        self.delete_object_version_metadata(version_id).await?;
        let changed_paths = if self.current_state_binding(key).await? != before_binding {
            touched_paths
        } else {
            BTreeSet::new()
        };
        self.persist_current_state_with_snapshot_batch(changed_paths, true, unix_ts())
            .await?;

        Ok(Some(DeleteObjectVersionOutcome {
            version_id: version_id.to_string(),
            was_delete_marker: record.manifest_hash == TOMBSTONE_MANIFEST_HASH,
            current_object_exists: self.object_id_for_key(key).await?.is_some(),
        }))
    }

    #[cfg(test)]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    #[cfg(test)]
    pub fn manifest_path_for_test(&self, manifest_hash: &str) -> PathBuf {
        manifest_path_from_hash(&self.manifests_dir, manifest_hash)
            .expect("test manifest hash should be a safe filename")
    }

    #[cfg(test)]
    pub fn chunk_path_for_test(&self, chunk_hash: &str) -> PathBuf {
        chunk_path_for_hash(&self.chunks_dir, chunk_hash).unwrap()
    }

    pub async fn object_count(&self) -> Result<usize> {
        self.metadata_store.count_current_objects().await
    }

    pub async fn current_keys(&self) -> Result<Vec<String>> {
        self.metadata_store.list_current_object_keys().await
    }

    /// Dashboard attribution for the resident `current_objects_cache`: how many entries
    /// are actually held in memory right now (bounded by its configured capacity)
    /// vs. the total live object count backing it in sqlite.
    pub fn current_objects_cache_stats(&self) -> CurrentObjectsCacheStats {
        let cache = self.current_objects_cache.lock().unwrap();
        CurrentObjectsCacheStats {
            resident_entries: cache.len(),
            capacity: cache.capacity(),
            estimated_resident_bytes: (cache.len() as u64)
                * CURRENT_OBJECT_CACHE_ENTRY_ESTIMATED_BYTES,
        }
    }

    #[cfg(test)]
    pub async fn list_cached_chunk_records_for_test(&self) -> Result<Vec<CachedChunkRecord>> {
        self.metadata_store.list_cached_chunk_records().await
    }

    #[cfg(test)]
    pub async fn list_locally_owned_manifests_for_test(&self) -> Result<Vec<String>> {
        self.metadata_store.list_locally_owned_manifests().await
    }

    #[cfg(test)]
    pub async fn load_manifest_payload_for_subject_for_test(
        &self,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<Option<Vec<u8>>> {
        let manifest_hash = match self
            .resolve_manifest_hash_for_key(key, None, version_id, ObjectReadMode::Preferred)
            .await
        {
            Ok(manifest_hash) => manifest_hash,
            Err(StoreReadError::NotFound) => return Ok(None),
            Err(StoreReadError::Corrupt(detail)) => bail!(detail),
            Err(StoreReadError::Internal(err)) => return Err(err),
        };

        let manifest_path = self.manifest_path_for_test(&manifest_hash);
        if !fs::try_exists(&manifest_path).await? {
            return Ok(None);
        }

        Ok(Some(fs::read(&manifest_path).await?))
    }

    #[cfg(test)]
    pub async fn replace_manifest_bytes_for_subject_for_test(
        &mut self,
        key: &str,
        version_id: Option<&str>,
        payload: &[u8],
    ) -> Result<String> {
        let manifest_hash = hash_hex(payload);
        let manifest_path = self.manifest_path_for_test(&manifest_hash);
        if let Some(parent) = manifest_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&manifest_path, payload).await?;

        if let Some(version_id) = version_id {
            let Some(object_id) = self
                .resolve_object_id_for_key_version(key, version_id)
                .await?
            else {
                bail!("missing object id for key={key} version_id={version_id}");
            };
            let Some(mut index) = self.load_version_index_by_object_id(&object_id).await? else {
                bail!("missing version index for key={key} version_id={version_id}");
            };
            let Some(record) = index.versions.get_mut(version_id) else {
                bail!("missing version record for key={key} version_id={version_id}");
            };
            record.manifest_hash = manifest_hash.clone();
            self.persist_version_index_by_object_id(&object_id, &index)
                .await?;

            if self.object_id_for_key(key).await?.as_deref() == Some(object_id.as_str())
                && index.preferred_head_version_id.as_deref() == Some(version_id)
            {
                self.upsert_current_object(
                    key,
                    CurrentObjectEntry {
                        manifest_hash: manifest_hash.clone(),
                        object_id: object_id.clone(),
                    },
                )
                .await?;
            }

            return Ok(manifest_hash);
        }

        if let Some(object_id) = self.object_id_for_key(key).await?
            && let Some(mut index) = self.load_version_index_by_object_id(&object_id).await?
        {
            let Some(preferred_head_version_id) = index.preferred_head_version_id.clone() else {
                bail!("missing preferred head for key={key}");
            };
            let Some(record) = index.versions.get_mut(&preferred_head_version_id) else {
                bail!("missing preferred head record for key={key}");
            };
            record.manifest_hash = manifest_hash.clone();
            self.persist_version_index_by_object_id(&object_id, &index)
                .await?;
            self.sync_current_state_for_key_from_index(key, &index)
                .await?;
            return Ok(manifest_hash);
        }

        self.upsert_current_object(
            key,
            CurrentObjectEntry {
                manifest_hash: manifest_hash.clone(),
                object_id: self
                    .object_id_for_key(key)
                    .await?
                    .with_context(|| format!("missing object id for current key {key}"))?,
            },
        )
        .await?;
        Ok(manifest_hash)
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
            let Some(object_id) = self
                .resolve_object_id_for_key_version(key, version_id)
                .await
                .map_err(StoreReadError::Internal)?
            else {
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
            match self
                .object_id_for_key(key)
                .await
                .map_err(StoreReadError::Internal)?
            {
                Some(object_id) => {
                    let index = self
                        .load_version_index_by_object_id(&object_id)
                        .await
                        .map_err(StoreReadError::Internal)?;
                    match index {
                        Some(index) => manifest_hash_for_read_mode(&index, read_mode),
                        None => self
                            .current_object_entry(key)
                            .await
                            .map_err(StoreReadError::Internal)?
                            .map(|entry| entry.manifest_hash),
                    }
                }
                None => self
                    .current_object_entry(key)
                    .await
                    .map_err(StoreReadError::Internal)?
                    .map(|entry| entry.manifest_hash),
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
            .await?
            .lookup_media_cache(manifest_hash)
            .await
    }

    #[cfg(test)]
    pub async fn ensure_media_cache(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        self.media_cache_worker()
            .ensure_media_cache(manifest_hash)
            .await
    }

    #[cfg(test)]
    pub async fn ensure_media_metadata(
        &self,
        manifest_hash: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        self.media_cache_worker()
            .ensure_media_metadata(manifest_hash)
            .await
    }

    pub async fn list_metadata_subjects(&self) -> Result<Vec<String>> {
        let snapshot = self.metadata_store.load_current_state().await?;
        let mut subjects: HashSet<String> = snapshot.objects.keys().cloned().collect();
        let mut indexed_object_ids = HashSet::new();
        for (path, object_id) in &snapshot.object_ids {
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

            for head_version_id in &index.head_version_ids {
                let Some(record) = index.versions.get(head_version_id) else {
                    continue;
                };
                let Some(key) = self.resolve_key_for_version_record(&index, record).await? else {
                    continue;
                };
                if record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
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
        let snapshot = self.metadata_store.load_current_state().await?;
        let mut subjects: HashSet<String> = HashSet::new();
        let mut indexed_object_ids = HashSet::new();

        for (key, manifest_hash) in &snapshot.objects {
            if self.manifest_is_fully_local(manifest_hash).await? {
                subjects.insert(key.clone());
            }
        }

        for (path, object_id) in &snapshot.object_ids {
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

            for head_version_id in &index.head_version_ids {
                let Some(record) = index.versions.get(head_version_id) else {
                    continue;
                };
                let Some(key) = self.resolve_key_for_version_record(&index, record).await? else {
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
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &hash)?;

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
        let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash.as_str())?;

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
            match validate_local_chunk_integrity(&self.chunks_dir, &chunk.hash, chunk.size_bytes)
                .await?
            {
                LocalChunkIntegrity::Valid => {}
                LocalChunkIntegrity::Missing => {
                    bail!(
                        "upload manifest references missing chunk hash={}",
                        chunk.hash
                    );
                }
                LocalChunkIntegrity::SizeMismatch { actual_size_bytes } => {
                    bail!(
                        "upload chunk size mismatch hash={} expected={} actual={}",
                        chunk.hash,
                        chunk.size_bytes,
                        actual_size_bytes
                    );
                }
                LocalChunkIntegrity::HashMismatch { actual_hash } => {
                    bail!(
                        "upload chunk hash mismatch hash={} actual={}",
                        chunk.hash,
                        actual_hash
                    );
                }
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
        let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash.as_str())?;
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
            .await?
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

            let touched_paths = BTreeSet::from([key.to_string()]);
            let before_binding = self.current_state_binding(key).await?;
            if create_snapshot {
                self.maybe_rotate_snapshot_batch(&touched_paths).await?;
            }
            self.sync_current_state_for_key_from_index(key, &index)
                .await?;
            let changed_paths = if self.current_state_binding(key).await? != before_binding {
                touched_paths
            } else {
                BTreeSet::new()
            };
            let snapshot_id = if let Some(snapshot_id) = self
                .persist_current_state_with_snapshot_batch(
                    changed_paths,
                    create_snapshot,
                    unix_ts(),
                )
                .await?
            {
                snapshot_id
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
        let touched_paths = BTreeSet::from([key.to_string()]);
        let before_binding = self.current_state_binding(key).await?;
        if create_snapshot {
            self.maybe_rotate_snapshot_batch(&touched_paths).await?;
        }

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
        self.sync_current_state_for_key_from_index(key, &index)
            .await?;
        let changed_paths = if self.current_state_binding(key).await? != before_binding {
            touched_paths
        } else {
            BTreeSet::new()
        };
        let snapshot_id = if let Some(snapshot_id) = self
            .persist_current_state_with_snapshot_batch(changed_paths, create_snapshot, unix_ts())
            .await?
        {
            snapshot_id
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
        let Some(object_id) = self.object_id_for_key(key).await? else {
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

        let touched_paths = BTreeSet::from([key.to_string()]);
        let before_binding = self.current_state_binding(key).await?;
        self.maybe_rotate_snapshot_batch(&touched_paths).await?;
        version.state = VersionConsistencyState::Confirmed;
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;
        self.sync_current_state_for_key_from_index(key, &index)
            .await?;
        let changed_paths = if self.current_state_binding(key).await? != before_binding {
            touched_paths
        } else {
            BTreeSet::new()
        };
        self.persist_current_state_with_snapshot_batch(changed_paths, true, unix_ts())
            .await?;

        Ok(true)
    }

    pub async fn list_versions(&self, key: &str) -> Result<Option<VersionGraphSummary>> {
        let Some(object_id) = self.object_id_for_key(key).await? else {
            return Ok(None);
        };
        self.version_graph_summary_for_object_id(key, &object_id)
            .await
    }

    pub async fn list_versions_with_history(
        &self,
        key: &str,
    ) -> Result<Option<VersionGraphSummary>> {
        let Some(object_id) = self.resolve_object_id_for_key_history(key).await? else {
            return Ok(None);
        };
        self.version_graph_summary_for_object_id(key, &object_id)
            .await
    }

    async fn version_graph_summary_for_object_id(
        &self,
        key: &str,
        object_id: &str,
    ) -> Result<Option<VersionGraphSummary>> {
        let Some(index) = self.load_version_index_by_object_id(object_id).await? else {
            return Ok(None);
        };

        let mut versions: Vec<VersionRecordSummary> = index
            .versions
            .values()
            .map(|record| VersionRecordSummary {
                version_id: record.version_id.clone(),
                manifest_hash: record.manifest_hash.clone(),
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

    pub async fn reconcile_legacy_rename_logical_paths(
        &mut self,
        dry_run: bool,
    ) -> Result<LegacyRenameLogicalPathReconcileReport> {
        let mut report = LegacyRenameLogicalPathReconcileReport {
            dry_run,
            ..LegacyRenameLogicalPathReconcileReport::default()
        };

        let object_ids = self.metadata_store.list_version_index_object_ids().await?;

        for object_id in object_ids {
            let Some(mut index) = self.load_version_index_by_object_id(&object_id).await? else {
                continue;
            };
            report.version_indexes_scanned = report.version_indexes_scanned.saturating_add(1);

            if !index
                .versions
                .keys()
                .any(|version_id| version_id.starts_with("ren-"))
            {
                report.skipped_indexes_without_rename_lineage = report
                    .skipped_indexes_without_rename_lineage
                    .saturating_add(1);
                continue;
            }

            let head_version_ids = index
                .head_version_ids
                .iter()
                .cloned()
                .collect::<HashSet<_>>();

            let mut index_changed = false;
            let mut version_ids = index.versions.keys().cloned().collect::<Vec<_>>();
            version_ids.sort();

            for version_id in version_ids {
                report.version_records_scanned = report.version_records_scanned.saturating_add(1);

                if head_version_ids.contains(&version_id) {
                    report.skipped_head_records = report.skipped_head_records.saturating_add(1);
                    continue;
                }

                let Some(record) = index.versions.get(&version_id).cloned() else {
                    continue;
                };

                if record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
                    report.skipped_tombstone_records =
                        report.skipped_tombstone_records.saturating_add(1);
                    continue;
                }

                let Some(logical_path) = record.logical_path.clone() else {
                    report.skipped_records_without_logical_path = report
                        .skipped_records_without_logical_path
                        .saturating_add(1);
                    continue;
                };

                let manifest = match self.load_manifest_by_hash(&record.manifest_hash).await {
                    Ok(Some(manifest)) => manifest,
                    Ok(None) => {
                        report.skipped_missing_manifests =
                            report.skipped_missing_manifests.saturating_add(1);
                        continue;
                    }
                    Err(_) => {
                        report.skipped_unreadable_manifests =
                            report.skipped_unreadable_manifests.saturating_add(1);
                        continue;
                    }
                };

                if manifest.key == logical_path {
                    continue;
                }

                report.manifest_key_mismatches_seen =
                    report.manifest_key_mismatches_seen.saturating_add(1);

                report.eligible_records = report.eligible_records.saturating_add(1);

                if report.sampled_updates.len() < LEGACY_RENAME_RECONCILE_UPDATE_SAMPLE_LIMIT {
                    report
                        .sampled_updates
                        .push(LegacyRenameLogicalPathReconcileUpdate {
                            object_id: index.object_id.clone(),
                            version_id: record.version_id.clone(),
                            manifest_hash: record.manifest_hash.clone(),
                            old_logical_path: logical_path,
                            corrected_logical_path: manifest.key.clone(),
                        });
                } else {
                    report.update_sample_truncated = true;
                }

                if !dry_run && let Some(record) = index.versions.get_mut(&version_id) {
                    record.logical_path = Some(manifest.key);
                    report.updated_records = report.updated_records.saturating_add(1);
                    index_changed = true;
                }
            }

            if index_changed {
                self.persist_version_index_by_object_id(&index.object_id, &index)
                    .await?;
            }
        }

        Ok(report)
    }

    pub async fn cleanup_duplicate_delete_recreate_loop_metadata(
        &mut self,
        dry_run: bool,
    ) -> Result<DeleteRecreateLoopCleanupReport> {
        let mut report = DeleteRecreateLoopCleanupReport {
            dry_run,
            ..DeleteRecreateLoopCleanupReport::default()
        };

        let mut candidate_groups =
            HashMap::<(String, String), Vec<DeleteRecreateLoopCleanupCandidate>>::new();
        let object_ids = self.metadata_store.list_version_index_object_ids().await?;

        for object_id in object_ids {
            let Some(index) = self.load_version_index_by_object_id(&object_id).await? else {
                continue;
            };
            report.version_indexes_scanned = report.version_indexes_scanned.saturating_add(1);

            match self
                .build_delete_recreate_loop_cleanup_candidate(index)
                .await?
            {
                DeleteRecreateLoopCleanupCandidateOutcome::Candidate(candidate) => {
                    report.eligible_single_path_indexes =
                        report.eligible_single_path_indexes.saturating_add(1);
                    let signature_key = serde_json::to_string(&candidate.signature)?;
                    candidate_groups
                        .entry((candidate.key.clone(), signature_key))
                        .or_default()
                        .push(*candidate);
                }
                DeleteRecreateLoopCleanupCandidateOutcome::UnresolvedPath => {
                    report.skipped_indexes_without_resolved_path = report
                        .skipped_indexes_without_resolved_path
                        .saturating_add(1);
                }
                DeleteRecreateLoopCleanupCandidateOutcome::MultiplePaths => {
                    report.skipped_indexes_with_multiple_paths =
                        report.skipped_indexes_with_multiple_paths.saturating_add(1);
                }
                DeleteRecreateLoopCleanupCandidateOutcome::NoDeleteRecreateLoop => {
                    report.skipped_indexes_without_delete_recreate_loop = report
                        .skipped_indexes_without_delete_recreate_loop
                        .saturating_add(1);
                }
            }
        }

        let mut duplicate_groups = candidate_groups
            .into_iter()
            .filter_map(|((key, _signature), mut candidates)| {
                if candidates.len() <= 1 {
                    return None;
                }
                candidates.sort_by(|a, b| a.object_id.cmp(&b.object_id));
                Some((key, candidates))
            })
            .collect::<Vec<_>>();
        duplicate_groups.sort_by(
            |(left_key, left_candidates), (right_key, right_candidates)| {
                left_key.cmp(right_key).then_with(|| {
                    left_candidates[0]
                        .object_id
                        .cmp(&right_candidates[0].object_id)
                })
            },
        );

        report.duplicate_groups = duplicate_groups.len();
        report.duplicate_indexes = duplicate_groups
            .iter()
            .map(|(_, candidates)| candidates.len())
            .sum();
        report.removable_indexes = duplicate_groups
            .iter()
            .map(|(_, candidates)| candidates.len().saturating_sub(1))
            .sum();

        let mut archive_writer = None;
        let archived_at_unix = unix_ts();
        if !dry_run && report.removable_indexes > 0 {
            let archive_dir = self
                .root_dir
                .join("state")
                .join("delete_recreate_loop_archive");
            fs::create_dir_all(&archive_dir).await?;
            let archive_file = archive_dir.join(format!("archive-{}.jsonl", unix_ts_nanos()));
            let writer = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&archive_file)
                .await
                .with_context(|| format!("failed to create {}", archive_file.display()))?;
            report.archive_path = Some(archive_file.to_string_lossy().to_string());
            archive_writer = Some(writer);
        }

        let mut current_state_changed = false;

        for (key, candidates) in duplicate_groups {
            let canonical_idx = select_delete_recreate_loop_cleanup_canonical(&candidates);
            let canonical = &candidates[canonical_idx];
            let removed = candidates
                .iter()
                .enumerate()
                .filter_map(|(idx, candidate)| {
                    if idx == canonical_idx {
                        None
                    } else {
                        Some(candidate)
                    }
                })
                .collect::<Vec<_>>();

            let mut version_ids = canonical
                .signature
                .versions
                .iter()
                .map(|record| record.version_id.clone())
                .collect::<Vec<_>>();
            version_ids.sort();

            let mut manifest_hashes = canonical
                .signature
                .versions
                .iter()
                .map(|record| record.manifest_hash.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            manifest_hashes.sort();

            if report.sampled_groups.len() < DELETE_RECREATE_LOOP_REPAIR_SAMPLE_LIMIT {
                report.sampled_groups.push(DeleteRecreateLoopCleanupGroup {
                    key: key.clone(),
                    kept_object_id: canonical.object_id.clone(),
                    removed_object_ids: removed
                        .iter()
                        .map(|candidate| candidate.object_id.clone())
                        .collect(),
                    preferred_head_version_id: canonical
                        .signature
                        .preferred_head_version_id
                        .clone(),
                    version_ids,
                    manifest_hashes,
                });
            } else {
                report.sampled_groups_truncated = true;
            }

            if dry_run {
                continue;
            }

            for candidate in removed {
                if let Some(writer) = archive_writer.as_mut() {
                    let mut line = serde_json::to_vec(&ArchivedDeleteRecreateLoopIndexRecord {
                        key: key.clone(),
                        kept_object_id: canonical.object_id.clone(),
                        removed_object_id: candidate.object_id.clone(),
                        archived_at_unix,
                        index: candidate.index.clone(),
                    })?;
                    line.push(b'\n');
                    writer.write_all(&line).await?;
                }

                self.delete_version_index_by_object_id(&candidate.object_id)
                    .await?;
                report.removed_indexes = report.removed_indexes.saturating_add(1);

                let stale_keys = self
                    .metadata_store
                    .list_keys_for_object_id(&candidate.object_id)
                    .await?;
                if !stale_keys.is_empty() {
                    current_state_changed = true;
                }
                for stale_key in stale_keys {
                    self.remove_current_object(&stale_key).await?;
                }
            }

            let before_binding = self.current_state_binding(&key).await?;
            self.sync_current_state_for_key_from_index(&key, &canonical.index)
                .await?;
            let stale_canonical_keys = self
                .metadata_store
                .list_keys_for_object_id(&canonical.object_id)
                .await?
                .into_iter()
                .filter(|current_key| current_key != &key)
                .collect::<Vec<_>>();
            if !stale_canonical_keys.is_empty() {
                current_state_changed = true;
            }
            for stale_key in stale_canonical_keys {
                self.remove_current_object(&stale_key).await?;
            }
            if self.current_state_binding(&key).await? != before_binding {
                current_state_changed = true;
            }
        }

        if let Some(writer) = archive_writer.as_mut() {
            writer.flush().await?;
        }
        if !dry_run && current_state_changed {
            self.create_snapshot().await?;
        }

        Ok(report)
    }

    pub async fn compact_snapshot_history(
        &mut self,
        dry_run: bool,
    ) -> Result<SnapshotHistoryCompactionReport> {
        let mut report = SnapshotHistoryCompactionReport {
            dry_run,
            max_batch_window_secs: SNAPSHOT_HISTORY_MAX_BATCH_WINDOW_SECS,
            ..SnapshotHistoryCompactionReport::default()
        };

        let mut snapshot_infos = self.metadata_store.list_snapshot_infos().await?;
        snapshot_infos.sort_by(|a, b| {
            a.created_at_unix
                .cmp(&b.created_at_unix)
                .then_with(|| a.id.cmp(&b.id))
        });

        report.snapshots_scanned = snapshot_infos.len();
        report.snapshots_before = snapshot_infos.len();
        if snapshot_infos.is_empty() {
            return Ok(report);
        }

        let mut retained_snapshot_ids = HashSet::<String>::new();
        let mut removable_snapshots = Vec::<SnapshotHistoryCompactionRemovedSnapshot>::new();
        let mut dirty_paths = HashSet::<String>::new();
        let mut batch_start_created_at_unix = None;
        let mut previous_snapshot: Option<SnapshotManifest> = None;
        let mut previous_snapshot_changed_paths = BTreeSet::<String>::new();

        for (index, info) in snapshot_infos.iter().enumerate() {
            let snapshot = self
                .metadata_store
                .load_snapshot_by_id(&info.id)
                .await?
                .with_context(|| format!("snapshot {} missing during compaction", info.id))?;

            let changed_paths = snapshot_changed_paths(previous_snapshot.as_ref(), &snapshot);
            if changed_paths.is_empty() {
                report.duplicate_state_snapshots =
                    report.duplicate_state_snapshots.saturating_add(1);
            }

            let has_overlap = !changed_paths.is_empty()
                && changed_paths
                    .iter()
                    .any(|path| dirty_paths.contains(path.as_str()));
            let exceeds_time_window = !changed_paths.is_empty()
                && batch_start_created_at_unix
                    .map(|started_at_unix| {
                        snapshot.created_at_unix.saturating_sub(started_at_unix)
                            > SNAPSHOT_HISTORY_MAX_BATCH_WINDOW_SECS
                    })
                    .unwrap_or(false);

            if index > 0 && (has_overlap || exceeds_time_window) {
                let previous_id = previous_snapshot
                    .as_ref()
                    .expect("previous snapshot known to be set when index > 0")
                    .id
                    .clone();
                retained_snapshot_ids.insert(previous_id);
                if has_overlap {
                    report.overlap_flush_boundaries =
                        report.overlap_flush_boundaries.saturating_add(1);
                }
                if exceeds_time_window {
                    report.time_window_flush_boundaries =
                        report.time_window_flush_boundaries.saturating_add(1);
                }
                dirty_paths.clear();
                batch_start_created_at_unix = None;
            }

            if !changed_paths.is_empty() {
                if batch_start_created_at_unix.is_none() {
                    batch_start_created_at_unix = Some(snapshot.created_at_unix);
                }
                dirty_paths.extend(changed_paths.iter().cloned());
            }

            if let Some(ref previous) = previous_snapshot {
                let reason = if previous_snapshot_changed_paths.is_empty() {
                    Some(SnapshotHistoryCompactionRemovalReason::DuplicateState)
                } else if !retained_snapshot_ids.contains(&previous.id) {
                    Some(SnapshotHistoryCompactionRemovalReason::BatchedDistinctPaths)
                } else {
                    None
                };

                if let Some(reason) = reason
                    && !retained_snapshot_ids.contains(&previous.id)
                {
                    removable_snapshots.push(SnapshotHistoryCompactionRemovedSnapshot {
                        snapshot_id: previous.id.clone(),
                        created_at_unix: previous.created_at_unix,
                        changed_path_count: previous_snapshot_changed_paths.len(),
                        sampled_changed_paths: previous_snapshot_changed_paths
                            .iter()
                            .take(SNAPSHOT_HISTORY_COMPACTION_CHANGED_PATH_SAMPLE_LIMIT)
                            .cloned()
                            .collect(),
                        reason,
                    });
                }
            }

            previous_snapshot = Some(snapshot);
            previous_snapshot_changed_paths = changed_paths;
        }

        let latest_snapshot_id = snapshot_infos
            .last()
            .expect("snapshot list is known to be non-empty")
            .id
            .clone();
        retained_snapshot_ids.insert(latest_snapshot_id);
        report.snapshots_retained = retained_snapshot_ids.len();
        report.removable_snapshots = removable_snapshots.len();
        report.sampled_removed_snapshots = removable_snapshots
            .iter()
            .take(SNAPSHOT_HISTORY_COMPACTION_SAMPLE_LIMIT)
            .cloned()
            .collect();
        report.sampled_removed_snapshots_truncated =
            removable_snapshots.len() > SNAPSHOT_HISTORY_COMPACTION_SAMPLE_LIMIT;

        if !dry_run && !removable_snapshots.is_empty() {
            let removable_ids = removable_snapshots
                .iter()
                .map(|snapshot| snapshot.snapshot_id.clone())
                .collect::<Vec<_>>();
            self.delete_snapshots_by_id(&removable_ids).await?;
            report.vacuumed_metadata_db = self.vacuum_metadata_store().await?;
            report.removed_snapshots = removable_ids.len();
        }

        Ok(report)
    }

    pub async fn compress_snapshot_json_data(
        &mut self,
        dry_run: bool,
    ) -> Result<CompressSnapshotJsonReport> {
        let total = self.metadata_store.list_snapshot_infos().await?.len();
        let uncompressed_ids = self.metadata_store.list_uncompressed_snapshot_ids().await?;
        let eligible = uncompressed_ids.len();
        let mut compressed = 0;

        if !dry_run && eligible > 0 {
            for id in &uncompressed_ids {
                if let Some(snapshot) = self.metadata_store.load_snapshot_by_id(id).await? {
                    self.metadata_store
                        .persist_snapshot_manifest(&snapshot)
                        .await?;
                    compressed += 1;
                }
            }
        }

        Ok(CompressSnapshotJsonReport {
            dry_run,
            snapshots_scanned: total,
            snapshots_eligible: eligible,
            snapshots_compressed: compressed,
            snapshots_already_compressed: total.saturating_sub(eligible),
        })
    }

    pub async fn has_manifest_for_key(&self, key: &str, manifest_hash: &str) -> Result<bool> {
        let Some(object_id) = self.object_id_for_key(key).await? else {
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
        let object_id = if let Some(version_id) = version_id {
            self.resolve_object_id_for_key_version(key, version_id)
                .await?
        } else {
            self.object_id_for_key(key).await?
        };
        let (
            selected_version_id,
            selected_logical_path,
            parent_version_ids,
            state,
            created_at_unix,
            copied_from_object_id,
            copied_from_version_id,
            copied_from_path,
            manifest_hash,
            selected_is_preferred_head,
        ) = if let Some(version_id) = version_id {
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
                record.logical_path.clone(),
                record.parent_version_ids.clone(),
                record.state.clone(),
                Some(record.created_at_unix),
                record.copied_from_object_id.clone(),
                record.copied_from_version_id.clone(),
                record.copied_from_path.clone(),
                record.manifest_hash.clone(),
                index.preferred_head_version_id.as_deref() == Some(record.version_id.as_str()),
            )
        } else {
            match object_id {
                Some(ref object_id) => {
                    match self.load_version_index_by_object_id(object_id).await? {
                        Some(index) => {
                            let Some(record) = version_record_for_read_mode(&index, read_mode)
                            else {
                                return Ok(None);
                            };

                            (
                                Some(record.version_id.clone()),
                                record.logical_path.clone(),
                                record.parent_version_ids.clone(),
                                record.state.clone(),
                                Some(record.created_at_unix),
                                record.copied_from_object_id.clone(),
                                record.copied_from_version_id.clone(),
                                record.copied_from_path.clone(),
                                record.manifest_hash.clone(),
                                true,
                            )
                        }
                        None => {
                            let Some(manifest_hash) = self
                                .current_object_entry(key)
                                .await?
                                .map(|entry| entry.manifest_hash)
                            else {
                                return Ok(None);
                            };
                            (
                                None,
                                Some(key.to_string()),
                                Vec::new(),
                                VersionConsistencyState::Confirmed,
                                None,
                                None,
                                None,
                                None,
                                manifest_hash,
                                true,
                            )
                        }
                    }
                }
                None => {
                    let Some(manifest_hash) = self
                        .current_object_entry(key)
                        .await?
                        .map(|entry| entry.manifest_hash)
                    else {
                        return Ok(None);
                    };
                    (
                        None,
                        Some(key.to_string()),
                        Vec::new(),
                        VersionConsistencyState::Confirmed,
                        None,
                        None,
                        None,
                        None,
                        manifest_hash,
                        true,
                    )
                }
            }
        };

        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(Some(ReplicationExportBundle {
                key: key.to_string(),
                object_id,
                version_id: selected_version_id,
                logical_path: selected_logical_path,
                parent_version_ids,
                state,
                created_at_unix,
                copied_from_object_id,
                copied_from_version_id,
                copied_from_path,
                selected_is_preferred_head,
                manifest_hash,
                manifest_bytes: Vec::new(),
                manifest: ReplicationManifestPayload {
                    key: key.to_string(),
                    total_size_bytes: 0,
                    chunks: Vec::new(),
                },
            }));
        }

        let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash.as_str())?;
        if !fs::try_exists(&manifest_path).await? {
            return Ok(None);
        }

        let manifest_bytes = fs::read(&manifest_path).await?;
        let manifest = serde_json::from_slice::<ObjectManifest>(&manifest_bytes)
            .with_context(|| format!("invalid manifest {}", manifest_path.display()))?;

        Ok(Some(ReplicationExportBundle {
            key: key.to_string(),
            object_id,
            version_id: selected_version_id,
            logical_path: selected_logical_path,
            parent_version_ids,
            state,
            created_at_unix,
            copied_from_object_id,
            copied_from_version_id,
            copied_from_path,
            selected_is_preferred_head,
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
        let object_id = if let Some(version_id) = version_id {
            self.resolve_object_id_for_key_version(key, version_id)
                .await?
        } else {
            self.object_id_for_key(key)
                .await?
                .or(self.resolve_object_id_for_key_history(key).await?)
        };

        let current_manifest_hash = self
            .current_object_entry(key)
            .await?
            .map(|entry| entry.manifest_hash);
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
        let chunk_path = chunk_path_for_hash(&self.chunks_dir, hash)?;
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
            self.persist_manifest_summary(manifest_hash, &manifest)
                .await?;
            for chunk in manifest.chunks {
                self.metadata_store
                    .delete_cached_chunk_record(&chunk.hash)
                    .await?;
            }
        }

        Ok(())
    }

    async fn persist_manifest_summary(
        &self,
        manifest_hash: &str,
        manifest: &ObjectManifest,
    ) -> Result<()> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(());
        }

        self.metadata_store
            .persist_manifest_summary(manifest_hash, &ManifestSummary::from_manifest(manifest))
            .await
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
        if referenced.is_empty() {
            return Ok(HashSet::new());
        }

        let referenced_vec = referenced.into_iter().collect::<Vec<_>>();
        self.metadata_store
            .filter_locally_owned_manifests(&referenced_vec)
            .await
    }

    pub async fn ingest_chunk(&self, hash: &str, payload: &[u8]) -> Result<bool> {
        self.chunk_ingestor.ingest_chunk(hash, payload).await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn ingest_chunk_auto(&self, payload: &[u8]) -> Result<(String, bool)> {
        self.chunk_ingestor.ingest_chunk_auto(payload).await
    }

    #[cfg_attr(not(test), allow(dead_code))]
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
            let object_id = if let Some(object_id) = self.object_id_for_key(key).await? {
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

            let touched_paths = BTreeSet::from([key.to_string()]);
            let before_binding = self.current_state_binding(key).await?;
            self.maybe_rotate_snapshot_batch(&touched_paths).await?;

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
            self.sync_current_state_for_key_from_index(key, &index)
                .await?;
            let changed_paths = if self.current_state_binding(key).await? != before_binding {
                touched_paths
            } else {
                BTreeSet::new()
            };
            self.persist_current_state_with_snapshot_batch(changed_paths, true, unix_ts())
                .await?;

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
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash)?;
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

        let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash)?;
        let manifest_needs_write = match fs::read(&manifest_path).await {
            Ok(existing_payload) => existing_payload != manifest_payload,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => true,
        };
        if manifest_needs_write {
            write_atomic_overwrite(&manifest_path, manifest_payload).await?;
        }
        self.mark_manifest_locally_owned(manifest_hash).await?;

        let object_id = self
            .object_id_for_key(key)
            .await?
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

        let touched_paths = BTreeSet::from([key.to_string()]);
        let before_binding = self.current_state_binding(key).await?;
        self.maybe_rotate_snapshot_batch(&touched_paths).await?;

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
        self.sync_current_state_for_key_from_index(key, &index)
            .await?;
        let changed_paths = if self.current_state_binding(key).await? != before_binding {
            touched_paths
        } else {
            BTreeSet::new()
        };
        self.persist_current_state_with_snapshot_batch(changed_paths, true, unix_ts())
            .await?;

        Ok(resolved_version_id)
    }

    pub async fn import_metadata_bundle(&mut self, bundle: &MetadataExportBundle) -> Result<bool> {
        let mut changed = false;
        let mut snapshot_changed_paths = BTreeSet::<String>::new();

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

            let parsed_manifest: ObjectManifest = serde_json::from_slice(&manifest.manifest_bytes)
                .context("invalid metadata manifest payload")?;

            let manifest_path =
                manifest_path_from_hash(&self.manifests_dir, manifest.manifest_hash.as_str())?;
            if !fs::try_exists(&manifest_path).await? {
                write_atomic(&manifest_path, &manifest.manifest_bytes).await?;
                changed = true;
            }
            self.persist_manifest_summary(&manifest.manifest_hash, &parsed_manifest)
                .await?;
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
            let mut touched_paths = BTreeSet::from([current_key.to_string()]);
            touched_paths.extend(
                self.metadata_store
                    .list_keys_for_object_id(&object_id)
                    .await?
                    .into_iter()
                    .filter(|key| Some(key.as_str()) != preferred_logical_path),
            );
            self.maybe_rotate_snapshot_batch(&touched_paths).await?;
            let before_binding = self.current_state_binding(current_key).await?;
            self.sync_current_state_for_key_from_index(current_key, &index)
                .await?;
            let stale_keys: Vec<String> = self
                .metadata_store
                .list_keys_for_object_id(&object_id)
                .await?
                .into_iter()
                .filter(|key| Some(key.as_str()) != preferred_logical_path)
                .collect();
            let removed_stale_keys = !stale_keys.is_empty();
            for stale_key in stale_keys {
                self.remove_current_object(&stale_key).await?;
            }
            if self.current_state_binding(current_key).await? != before_binding
                || removed_stale_keys
            {
                current_state_changed = true;
                snapshot_changed_paths.extend(touched_paths);
            }
        } else if let Some(manifest_hash) = bundle.current_manifest_hash.as_ref() {
            let object_id = bundle.object_id.clone().unwrap_or_else(generate_object_id);
            let expected_entry = CurrentObjectEntry {
                manifest_hash: manifest_hash.clone(),
                object_id: object_id.clone(),
            };
            if self.current_object_entry(&bundle.key).await? != Some(expected_entry.clone()) {
                let touched_paths = BTreeSet::from([bundle.key.clone()]);
                self.maybe_rotate_snapshot_batch(&touched_paths).await?;
                self.upsert_current_object(&bundle.key, expected_entry)
                    .await?;
                current_state_changed = true;
                snapshot_changed_paths.extend(touched_paths);
            }
        }

        if current_state_changed {
            self.persist_current_state_with_snapshot_batch(snapshot_changed_paths, true, unix_ts())
                .await?;
            changed = true;
        }

        Ok(changed)
    }

    pub async fn import_replication_bundle(
        &mut self,
        bundle: &ReplicationExportBundle,
    ) -> Result<String> {
        let key = bundle
            .logical_path
            .as_deref()
            .unwrap_or(bundle.key.as_str());
        let resolved_version_id = bundle.version_id.clone().unwrap_or_else(|| {
            if bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH {
                format!("rep-{}-tombstone", unix_ts_nanos())
            } else {
                format!("rep-{}-{}", unix_ts_nanos(), &bundle.manifest_hash[..12])
            }
        });
        let source_created_at_unix = bundle.created_at_unix.unwrap_or_else(unix_ts);

        if bundle.manifest_hash != TOMBSTONE_MANIFEST_HASH {
            let computed_manifest_hash = hash_hex(&bundle.manifest_bytes);
            if computed_manifest_hash != bundle.manifest_hash {
                bail!(
                    "manifest hash mismatch: expected={} actual={computed_manifest_hash}",
                    bundle.manifest_hash
                );
            }

            let manifest = serde_json::from_slice::<ObjectManifest>(&bundle.manifest_bytes)
                .context("invalid replication manifest payload")?;

            if manifest.key != key {
                bail!(
                    "replication manifest key mismatch: expected={key} actual={}",
                    manifest.key
                );
            }

            for chunk in &manifest.chunks {
                let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash)?;
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

            let manifest_path =
                manifest_path_from_hash(&self.manifests_dir, bundle.manifest_hash.as_str())?;
            let manifest_needs_write = match fs::read(&manifest_path).await {
                Ok(existing_payload) => existing_payload != bundle.manifest_bytes,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => true,
            };
            if manifest_needs_write {
                write_atomic_overwrite(&manifest_path, &bundle.manifest_bytes).await?;
            }
            self.mark_manifest_locally_owned(&bundle.manifest_hash)
                .await?;
        }

        let lineage_choice = self
            .choose_replication_bundle_object_id(
                bundle,
                key,
                &resolved_version_id,
                source_created_at_unix,
            )
            .await?;
        let object_id = lineage_choice.object_id.clone();
        let created_at_unix = if lineage_choice.conflict_recreated
            && bundle.manifest_hash != TOMBSTONE_MANIFEST_HASH
        {
            source_created_at_unix.max(unix_ts()).saturating_add(1)
        } else {
            source_created_at_unix
        };
        let mut index = self
            .load_version_index_by_object_id(&object_id)
            .await?
            .unwrap_or_else(|| empty_version_index(&object_id));

        let record = FileVersionRecord {
            version_id: resolved_version_id.clone(),
            object_id: object_id.clone(),
            manifest_hash: bundle.manifest_hash.clone(),
            logical_path: Some(key.to_string()),
            parent_version_ids: bundle.parent_version_ids.clone(),
            state: bundle.state.clone(),
            created_at_unix,
            copied_from_object_id: bundle.copied_from_object_id.clone(),
            copied_from_version_id: bundle.copied_from_version_id.clone(),
            copied_from_path: bundle.copied_from_path.clone(),
        };

        self.prune_conflicting_replication_bundle_versions(key, &record)
            .await?;
        let touched_paths = BTreeSet::from([key.to_string()]);
        let before_binding = self.current_state_binding(key).await?;
        self.maybe_rotate_snapshot_batch(&touched_paths).await?;

        if let Some(existing) = index.versions.get(&resolved_version_id) {
            if !replication_bundle_record_matches(existing, &record) {
                index.versions.insert(resolved_version_id.clone(), record);
                index.head_version_ids = recompute_head_version_ids(&index);
                index.preferred_head_version_id = choose_preferred_head(&index);
                self.persist_version_index_by_object_id(&object_id, &index)
                    .await?;
                self.sync_current_state_for_key_from_index(key, &index)
                    .await?;
                if bundle.selected_is_preferred_head
                    && bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH
                {
                    self.apply_selected_replica_tombstone_current_state(key, bundle)
                        .await?;
                } else if bundle.selected_is_preferred_head {
                    self.promote_current_state_for_key_from_index(key, &index)
                        .await?;
                }
                let changed_paths = if self.current_state_binding(key).await? != before_binding {
                    touched_paths.clone()
                } else {
                    BTreeSet::new()
                };
                self.persist_current_state_with_snapshot_batch(
                    changed_paths,
                    true,
                    created_at_unix,
                )
                .await?;
                return Ok(resolved_version_id);
            }

            self.sync_current_state_for_key_from_index(key, &index)
                .await?;
            if bundle.selected_is_preferred_head && bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH
            {
                self.apply_selected_replica_tombstone_current_state(key, bundle)
                    .await?;
            } else if bundle.selected_is_preferred_head {
                self.promote_current_state_for_key_from_index(key, &index)
                    .await?;
            }
            let changed_paths = if self.current_state_binding(key).await? != before_binding {
                touched_paths.clone()
            } else {
                BTreeSet::new()
            };
            self.persist_current_state_with_snapshot_batch(changed_paths, true, created_at_unix)
                .await?;
            return Ok(resolved_version_id);
        }

        index.versions.insert(resolved_version_id.clone(), record);
        index.head_version_ids = recompute_head_version_ids(&index);
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;
        self.sync_current_state_for_key_from_index(key, &index)
            .await?;
        if bundle.selected_is_preferred_head && bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH {
            self.apply_selected_replica_tombstone_current_state(key, bundle)
                .await?;
        } else if bundle.selected_is_preferred_head {
            self.promote_current_state_for_key_from_index(key, &index)
                .await?;
        }
        let changed_paths = if self.current_state_binding(key).await? != before_binding {
            touched_paths
        } else {
            BTreeSet::new()
        };
        self.persist_current_state_with_snapshot_batch(changed_paths, true, created_at_unix)
            .await?;

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

        let Some(object_id) = self.object_id_for_key(key).await? else {
            return Ok(false);
        };

        let Some(mut index) = self.load_version_index_by_object_id(&object_id).await? else {
            return Ok(false);
        };

        if index.versions.remove(version_id).is_none() {
            return Ok(false);
        }

        let touched_paths = BTreeSet::from([key.to_string()]);
        let before_binding = self.current_state_binding(key).await?;
        self.maybe_rotate_snapshot_batch(&touched_paths).await?;
        index.head_version_ids = recompute_head_version_ids(&index);
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index_by_object_id(&object_id, &index)
            .await?;
        self.sync_current_state_for_key_from_index(key, &index)
            .await?;
        let changed_paths = if self.current_state_binding(key).await? != before_binding {
            touched_paths
        } else {
            BTreeSet::new()
        };
        self.persist_current_state_with_snapshot_batch(changed_paths, true, unix_ts())
            .await?;

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
        let snapshot = self.metadata_store.load_current_state().await?;
        for (path, object_id) in &snapshot.object_ids {
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
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash)?;
        if !fs::try_exists(&manifest_path).await? {
            return Ok(None);
        }

        let payload = fs::read(&manifest_path).await?;
        let manifest = serde_json::from_slice::<ObjectManifest>(&payload)
            .with_context(|| format!("invalid manifest {}", manifest_path.display()))?;
        Ok(Some(manifest))
    }

    async fn load_manifest_payload_by_hash(&self, manifest_hash: &str) -> Result<Option<Vec<u8>>> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash)?;
        if !fs::try_exists(&manifest_path).await? {
            return Ok(None);
        }
        Ok(Some(fs::read(&manifest_path).await?))
    }

    async fn local_chunk_matches_ref(&self, chunk: &ChunkRef) -> Result<bool> {
        Ok(matches!(
            validate_local_chunk_integrity(&self.chunks_dir, &chunk.hash, chunk.size_bytes).await?,
            LocalChunkIntegrity::Valid
        ))
    }

    #[cfg(test)]
    async fn manifest_is_fully_local(&self, manifest_hash: &str) -> Result<bool> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(true);
        }

        let manifest = match self.load_manifest_by_hash(manifest_hash).await {
            Ok(Some(manifest)) => manifest,
            Ok(None) => return Ok(false),
            Err(err) => {
                warn!(
                    manifest_hash = %manifest_hash,
                    error = %err,
                    "manifest unreadable or invalid; treating as not locally available"
                );
                return Ok(false);
            }
        };

        for chunk in &manifest.chunks {
            if !matches!(
                validate_local_chunk_integrity(&self.chunks_dir, &chunk.hash, chunk.size_bytes)
                    .await?,
                LocalChunkIntegrity::Valid
            ) {
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
        let manifest_path =
            manifest_path_from_hash(&self.manifests_dir, cloned_manifest_hash.as_str())?;
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
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash)
                .map_err(StoreReadError::Internal)?;
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
    async fn persist_media_cache_record(&self, metadata: &CachedMediaMetadata) -> Result<()> {
        persist_media_cache_record_with_payload(
            &self.media_thumbnails_dir,
            self.metadata_store.as_ref(),
            metadata,
            None,
        )
        .await
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

            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash)
                .map_err(StoreReadError::Internal)?;
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

            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash)
                .map_err(StoreReadError::Internal)?;
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

            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash)
                .map_err(StoreReadError::Internal)?;
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

        let snapshot = self.metadata_store.load_current_state().await?;
        for existing_key in snapshot.objects.keys() {
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

        let touched_paths = targets.clone();
        let mut before_bindings = HashMap::with_capacity(touched_paths.len());
        for path in &touched_paths {
            before_bindings.insert(path.clone(), self.current_state_binding(path).await?);
        }
        if options.create_snapshot {
            self.maybe_rotate_snapshot_batch(&touched_paths).await?;
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
            let changed_paths = self.changed_paths_after_bindings(&before_bindings).await?;
            if !changed_paths.is_empty() {
                self.record_snapshot_batch(changed_paths, unix_ts()).await?;
            }
        }

        Ok(results)
    }

    pub async fn tombstone_object(&mut self, key: &str, options: PutOptions) -> Result<String> {
        let object_id = self
            .object_id_for_key(key)
            .await?
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

            let touched_paths = BTreeSet::from([key.to_string()]);
            let before_binding = self.current_state_binding(key).await?;
            if options.create_snapshot {
                self.maybe_rotate_snapshot_batch(&touched_paths).await?;
            }
            self.sync_current_state_for_key_from_index(key, &index)
                .await?;
            let changed_paths = if self.current_state_binding(key).await? != before_binding {
                touched_paths
            } else {
                BTreeSet::new()
            };
            let _snapshot_id = if self
                .persist_current_state_with_snapshot_batch(
                    changed_paths,
                    options.create_snapshot,
                    unix_ts(),
                )
                .await?
                .is_some()
            {
                version_id.clone()
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
        let touched_paths = BTreeSet::from([key.to_string()]);
        let before_binding = self.current_state_binding(key).await?;
        if options.create_snapshot {
            self.maybe_rotate_snapshot_batch(&touched_paths).await?;
        }

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
        self.sync_current_state_for_key_from_index(key, &index)
            .await?;
        let changed_paths = if self.current_state_binding(key).await? != before_binding {
            touched_paths
        } else {
            BTreeSet::new()
        };
        self.persist_current_state_with_snapshot_batch(
            changed_paths,
            options.create_snapshot,
            unix_ts(),
        )
        .await?;

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

        let Some(source_entry) = self.current_object_entry(from_path).await? else {
            return Ok(PathMutationResult::SourceMissing);
        };
        let object_id = source_entry.object_id;

        if self.current_object_entry(to_path).await?.is_some() {
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

        let touched_paths = BTreeSet::from([from_path.to_string(), to_path.to_string()]);
        self.maybe_rotate_snapshot_batch(&touched_paths).await?;

        let renamed_manifest_hash = self
            .clone_manifest_for_key(&source_head.manifest_hash, to_path)
            .await?;
        let renamed_version_id =
            format!("ren-{}-{}", unix_ts_nanos(), &renamed_manifest_hash[..12]);
        let source_head_version_id = source_head.version_id.clone();

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

        self.remove_current_object(from_path).await?;
        self.upsert_current_object(
            to_path,
            CurrentObjectEntry {
                manifest_hash: renamed_manifest_hash,
                object_id,
            },
        )
        .await?;

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

        self.persist_current_state_with_snapshot_batch(touched_paths, true, unix_ts())
            .await?;

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

        let Some(source_object_id) = self.object_id_for_key(from_path).await? else {
            return Ok(PathMutationResult::SourceMissing);
        };

        if self.current_object_entry(to_path).await?.is_some() && !overwrite {
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

        let touched_paths = BTreeSet::from([to_path.to_string()]);
        self.maybe_rotate_snapshot_batch(&touched_paths).await?;

        let copied_manifest_hash = self
            .clone_manifest_for_key(&source_head.manifest_hash, to_path)
            .await?;
        self.persist_copied_version_to_target(
            from_path,
            to_path,
            copied_manifest_hash,
            Some(source_object_id),
            Some(source_head.version_id.clone()),
            source_head.state.clone(),
            "copy",
            true,
        )
        .await
    }

    pub async fn restore_snapshot_path(
        &mut self,
        snapshot_id: &str,
        from_path: &str,
        to_path: &str,
        recursive: bool,
        overwrite: bool,
    ) -> Result<SnapshotRestoreMutationResult> {
        let Some(snapshot_manifest) = self
            .metadata_store
            .load_snapshot_manifest(snapshot_id)
            .await?
        else {
            return Ok(SnapshotRestoreMutationResult::SourceMissing);
        };
        let snapshot_state = SnapshotObjectState {
            created_at_unix: snapshot_manifest.created_at_unix,
            objects: snapshot_manifest.objects,
            object_ids: snapshot_manifest.object_ids,
        };

        if recursive {
            let mut source_paths: Vec<String> = snapshot_state
                .objects
                .keys()
                .filter(|candidate| *candidate == from_path || candidate.starts_with(from_path))
                .cloned()
                .collect();
            source_paths.sort();
            if source_paths.is_empty() {
                return Ok(SnapshotRestoreMutationResult::SourceMissing);
            }

            if from_path != to_path
                && let Some(conflict_path) = self
                    .metadata_store
                    .load_current_state()
                    .await?
                    .object_ids
                    .into_keys()
                    .find(|candidate| candidate == to_path || candidate.starts_with(to_path))
            {
                if !overwrite {
                    return Ok(SnapshotRestoreMutationResult::TargetExists {
                        path: conflict_path,
                    });
                }
                return Ok(SnapshotRestoreMutationResult::TargetExists {
                    path: conflict_path,
                });
            }

            let changed_paths = source_paths
                .iter()
                .filter_map(|source_candidate| {
                    source_candidate
                        .strip_prefix(from_path)
                        .map(|suffix| format!("{to_path}{suffix}"))
                })
                .collect::<BTreeSet<_>>();
            let mut before_bindings = HashMap::with_capacity(changed_paths.len());
            for path in &changed_paths {
                before_bindings.insert(path.clone(), self.current_state_binding(path).await?);
            }
            if !changed_paths.is_empty() {
                self.maybe_rotate_snapshot_batch(&changed_paths).await?;
            }
            for source_candidate in &source_paths {
                let Some(suffix) = source_candidate.as_str().strip_prefix(from_path) else {
                    continue;
                };
                let target_candidate = format!("{to_path}{suffix}");
                match self
                    .restore_snapshot_object_path_inner(
                        &snapshot_state,
                        source_candidate,
                        &target_candidate,
                        false,
                        overwrite,
                    )
                    .await?
                {
                    PathMutationResult::Applied => {}
                    PathMutationResult::SourceMissing => {
                        return Ok(SnapshotRestoreMutationResult::SourceMissing);
                    }
                    PathMutationResult::TargetExists => {
                        return Ok(SnapshotRestoreMutationResult::TargetExists {
                            path: target_candidate,
                        });
                    }
                }
            }

            let changed_paths = self.changed_paths_after_bindings(&before_bindings).await?;
            if !changed_paths.is_empty() {
                self.record_snapshot_batch(changed_paths, unix_ts()).await?;
            }
            return Ok(SnapshotRestoreMutationResult::Applied(
                SnapshotRestoreReport {
                    snapshot_id: snapshot_id.to_string(),
                    source_path: from_path.to_string(),
                    target_path: to_path.to_string(),
                    recursive: true,
                    restored_count: source_paths.len(),
                },
            ));
        }

        match self
            .restore_snapshot_object_path_inner(
                &snapshot_state,
                from_path,
                to_path,
                true,
                overwrite,
            )
            .await?
        {
            PathMutationResult::Applied => Ok(SnapshotRestoreMutationResult::Applied(
                SnapshotRestoreReport {
                    snapshot_id: snapshot_id.to_string(),
                    source_path: from_path.to_string(),
                    target_path: to_path.to_string(),
                    recursive: false,
                    restored_count: 1,
                },
            )),
            PathMutationResult::SourceMissing => Ok(SnapshotRestoreMutationResult::SourceMissing),
            PathMutationResult::TargetExists => Ok(SnapshotRestoreMutationResult::TargetExists {
                path: to_path.to_string(),
            }),
        }
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
        limit: Option<usize>,
        collected_since_unix: Option<u64>,
    ) -> Result<Vec<StorageStatsSample>> {
        self.metadata_store
            .list_storage_stats_history(limit, collected_since_unix)
            .await
    }

    #[cfg(test)]
    pub async fn persist_storage_stats_sample(&self, sample: &StorageStatsSample) -> Result<()> {
        self.storage_stats_collector()
            .persist_storage_stats_sample(sample)
            .await
    }

    #[cfg(test)]
    pub async fn persist_repair_run_record_for_test(&self, record: &RepairRunRecord) -> Result<()> {
        self.metadata_store.persist_repair_run_record(record).await
    }

    #[cfg(test)]
    pub async fn persist_manual_repair_action_run_record_for_test(
        &self,
        record: &ManualRepairActionRunRecord,
    ) -> Result<()> {
        self.metadata_store
            .persist_manual_repair_action_run_record(record)
            .await
    }

    #[cfg(test)]
    pub async fn persist_data_scrub_run_record_for_test(
        &self,
        record: &DataScrubRunRecord,
    ) -> Result<()> {
        self.metadata_store
            .persist_data_scrub_run_record(record)
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

    #[cfg(test)]
    pub async fn prune_repair_run_history_before_for_test(
        &self,
        finished_before_unix: u64,
    ) -> Result<()> {
        self.metadata_store
            .prune_repair_run_history_before(finished_before_unix)
            .await
    }

    #[cfg(test)]
    pub async fn prune_manual_repair_action_run_history_before_for_test(
        &self,
        finished_before_unix: u64,
    ) -> Result<()> {
        self.metadata_store
            .prune_manual_repair_action_run_history_before(finished_before_unix)
            .await
    }

    #[cfg(test)]
    pub async fn prune_data_scrub_run_history_before_for_test(
        &self,
        finished_before_unix: u64,
    ) -> Result<()> {
        self.metadata_store
            .prune_data_scrub_run_history_before(finished_before_unix)
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
        let manifest_hashes = self.list_manifest_hashes().await?;
        let cached_chunk_records = self.metadata_store.list_cached_chunk_records().await?;
        let tracked_cached_chunks = cached_chunk_records.len();
        let cached_chunk_hashes = cached_chunk_records
            .iter()
            .map(|record| record.hash.clone())
            .collect::<HashSet<_>>();

        let mut retained_manifests = referenced_manifests.clone();
        let mut skipped_recent_manifests = 0usize;
        let mut deleted_manifests = 0usize;

        for manifest_hash in &manifest_hashes {
            if referenced_manifests.contains(manifest_hash) {
                continue;
            }

            let manifest_path = manifest_path_from_hash(&self.manifests_dir, manifest_hash)?;
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

        // Only the retained set (referenced, or too-recent-to-reap) ever needs its
        // content inspected, and even that is read one bounded batch at a time so peak
        // resident manifest data stays flat as the store grows instead of scaling with
        // total manifest count (see docs/node-memory-footprint-reduction-plan.md Slice 3).
        let mut protected_chunks = HashSet::<String>::new();
        let mut protected_media_fingerprints = HashSet::<String>::new();
        let mut peak_manifest_batch_size = 0usize;
        let retained_manifest_hashes: Vec<&String> = retained_manifests.iter().collect();
        for batch in retained_manifest_hashes.chunks(self.gc_manifest_load_batch_size.max(1)) {
            peak_manifest_batch_size = peak_manifest_batch_size.max(batch.len());
            for manifest_hash in batch {
                let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
                    continue;
                };
                protected_media_fingerprints.insert(content_fingerprint_from_manifest(&manifest));
                if owned_referenced_manifests.contains(*manifest_hash) {
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

                let chunk_path = chunk_path_for_hash(&self.chunks_dir, &record.hash)?;
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
            retained_manifests_processed: retained_manifest_hashes.len(),
            peak_manifest_batch_size,
        })
    }

    pub async fn clear_media_cache(&self) -> Result<MediaCacheClearReport> {
        let mut fingerprints = self.list_media_cache_fingerprints().await?;
        fingerprints.sort_unstable();
        fingerprints.dedup();

        for content_fingerprint in &fingerprints {
            self.metadata_store
                .delete_media_cache_record(content_fingerprint)
                .await?;
        }

        let (deleted_thumbnail_files, deleted_thumbnail_bytes) =
            directory_file_stats(&self.media_thumbnails_dir).await?;
        if fs::try_exists(&self.media_thumbnails_dir).await? {
            fs::remove_dir_all(&self.media_thumbnails_dir).await?;
        }
        fs::create_dir_all(&self.media_thumbnails_dir).await?;

        Ok(MediaCacheClearReport {
            deleted_metadata_records: fingerprints.len(),
            deleted_thumbnail_files,
            deleted_thumbnail_bytes,
            cleared_at_unix: unix_ts(),
        })
    }

    pub async fn clear_media_cache_for_manifest(&self, manifest_hash: &str) -> Result<String> {
        if manifest_hash == TOMBSTONE_MANIFEST_HASH {
            bail!("cannot clear media cache for tombstone manifest");
        }

        let Some(manifest) = self.load_manifest_by_hash(manifest_hash).await? else {
            bail!("missing manifest for hash={manifest_hash}");
        };

        let content_fingerprint = content_fingerprint_from_manifest(&manifest);
        self.metadata_store
            .delete_media_cache_record(&content_fingerprint)
            .await?;

        let thumb_dir = self.media_thumbnails_dir.join(&content_fingerprint);
        if fs::try_exists(&thumb_dir).await? {
            fs::remove_dir_all(&thumb_dir).await?;
        }

        Ok(content_fingerprint)
    }

    pub async fn compact_tombstone_indexes(
        &self,
        retention_secs: u64,
        dry_run: bool,
    ) -> Result<TombstoneCompactionReport> {
        let now = unix_ts();
        let bound_object_ids: HashSet<String> = self
            .metadata_store
            .load_current_state()
            .await?
            .object_ids
            .into_values()
            .collect();

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

    pub async fn append_data_change_event(&self, event: &DataChangeEvent) -> Result<()> {
        self.metadata_store.append_data_change_event(event).await
    }

    async fn current_object_entry(&self, key: &str) -> Result<Option<CurrentObjectEntry>> {
        if let Some(entry) = self
            .current_objects_cache
            .lock()
            .unwrap()
            .get(&key.to_string())
        {
            return Ok(Some((*entry).clone()));
        }

        let fetched = self.metadata_store.get_current_object(key).await?;
        if let Some(entry) = &fetched {
            self.current_objects_cache
                .lock()
                .unwrap()
                .insert(key.to_string(), entry.clone());
        }
        Ok(fetched)
    }

    async fn upsert_current_object(&self, key: &str, entry: CurrentObjectEntry) -> Result<()> {
        self.metadata_store
            .upsert_current_object(key, &entry)
            .await?;
        self.current_objects_cache
            .lock()
            .unwrap()
            .insert(key.to_string(), entry);
        Ok(())
    }

    async fn remove_current_object(&self, key: &str) -> Result<()> {
        self.metadata_store.remove_current_object(key).await?;
        self.current_objects_cache
            .lock()
            .unwrap()
            .remove(&key.to_string());
        Ok(())
    }

    async fn object_id_for_key(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .current_object_entry(key)
            .await?
            .map(|entry| entry.object_id))
    }

    async fn current_state_binding(&self, key: &str) -> Result<(Option<String>, Option<String>)> {
        Ok(match self.current_object_entry(key).await? {
            Some(entry) => (Some(entry.manifest_hash), Some(entry.object_id)),
            None => (None, None),
        })
    }

    async fn changed_paths_after_bindings(
        &self,
        before: &HashMap<String, (Option<String>, Option<String>)>,
    ) -> Result<BTreeSet<String>> {
        let mut changed = BTreeSet::new();
        for (path, binding) in before {
            if self.current_state_binding(path).await? != *binding {
                changed.insert(path.clone());
            }
        }
        Ok(changed)
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

    async fn sync_current_state_for_key_from_index(
        &self,
        key: &str,
        index: &FileVersionIndex,
    ) -> Result<()> {
        let current_object_id = self.object_id_for_key(key).await?;
        let Some(preferred_head) = &index.preferred_head_version_id else {
            if current_object_id.as_deref() == Some(index.object_id.as_str()) {
                self.remove_current_object(key).await?;
            }
            return Ok(());
        };

        let preferred_record = index.versions.get(preferred_head).with_context(|| {
            format!("preferred head {preferred_head} missing in index for key={key}")
        })?;

        if preferred_record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
            if current_object_id.as_deref() == Some(index.object_id.as_str()) {
                self.remove_current_object(key).await?;
            }
            return Ok(());
        }

        if current_object_id.is_none()
            || current_object_id.as_deref() == Some(index.object_id.as_str())
        {
            self.upsert_current_object(
                key,
                CurrentObjectEntry {
                    manifest_hash: preferred_record.manifest_hash.clone(),
                    object_id: index.object_id.clone(),
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn promote_current_state_for_key_from_index(
        &self,
        key: &str,
        index: &FileVersionIndex,
    ) -> Result<()> {
        let Some(preferred_head) = &index.preferred_head_version_id else {
            return Ok(());
        };
        let preferred_record = index.versions.get(preferred_head).with_context(|| {
            format!("preferred head {preferred_head} missing in index for key={key}")
        })?;
        if preferred_record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(());
        }

        self.upsert_current_object(
            key,
            CurrentObjectEntry {
                manifest_hash: preferred_record.manifest_hash.clone(),
                object_id: index.object_id.clone(),
            },
        )
        .await
    }

    async fn apply_selected_replica_tombstone_current_state(
        &self,
        key: &str,
        bundle: &ReplicationExportBundle,
    ) -> Result<()> {
        let Some(current_object_id) = self.object_id_for_key(key).await? else {
            return Ok(());
        };

        let same_lineage = bundle.object_id.as_deref() == Some(current_object_id.as_str());
        let copied_from_current = bundle.copied_from_object_id.as_deref()
            == Some(current_object_id.as_str())
            && bundle.copied_from_path.as_deref() == Some(key);
        let tombstone_supersedes_current = self
            .replica_tombstone_supersedes_current_key(key, &current_object_id, bundle)
            .await?;

        if same_lineage || copied_from_current || tombstone_supersedes_current {
            self.remove_current_object(key).await?;
        }
        Ok(())
    }

    async fn restore_object_path_from_source(
        &mut self,
        source: SnapshotRestoreSource,
        source_path: &str,
        target_path: &str,
        create_snapshot: bool,
        overwrite: bool,
    ) -> Result<PathMutationResult> {
        if source_path != target_path
            && self.current_object_entry(target_path).await?.is_some()
            && !overwrite
        {
            return Ok(PathMutationResult::TargetExists);
        }

        let touched_paths = BTreeSet::from([target_path.to_string()]);
        if create_snapshot {
            self.maybe_rotate_snapshot_batch(&touched_paths).await?;
        }
        let restored_manifest_hash = self
            .clone_manifest_for_key(&source.manifest_hash, target_path)
            .await?;

        self.persist_copied_version_to_target(
            source_path,
            target_path,
            restored_manifest_hash,
            source.object_id,
            source.version_id,
            source.state,
            "restore",
            create_snapshot,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn persist_copied_version_to_target(
        &mut self,
        source_path: &str,
        target_path: &str,
        manifest_hash: String,
        copied_from_object_id: Option<String>,
        copied_from_version_id: Option<String>,
        state: VersionConsistencyState,
        version_prefix: &str,
        create_snapshot: bool,
    ) -> Result<PathMutationResult> {
        let touched_paths = BTreeSet::from([target_path.to_string()]);
        let target_object_id = self
            .object_id_for_key(target_path)
            .await?
            .unwrap_or_else(generate_object_id);
        let mut target_index = self
            .load_version_index_by_object_id(&target_object_id)
            .await?
            .unwrap_or_else(|| empty_version_index(&target_object_id));
        let copied_version_id = format!(
            "{version_prefix}-{}-{}",
            unix_ts_nanos(),
            &manifest_hash[..12]
        );
        let parent_version_ids = target_index
            .preferred_head_version_id
            .iter()
            .cloned()
            .collect();

        target_index.versions.insert(
            copied_version_id.clone(),
            FileVersionRecord {
                version_id: copied_version_id,
                object_id: target_object_id.clone(),
                manifest_hash,
                logical_path: Some(target_path.to_string()),
                parent_version_ids,
                state,
                created_at_unix: unix_ts(),
                copied_from_object_id,
                copied_from_version_id,
                copied_from_path: Some(source_path.to_string()),
            },
        );
        target_index.head_version_ids = recompute_head_version_ids(&target_index);
        target_index.preferred_head_version_id = choose_preferred_head(&target_index);
        self.persist_version_index_by_object_id(&target_object_id, &target_index)
            .await?;
        self.sync_current_state_for_key_from_index(target_path, &target_index)
            .await?;
        self.persist_current_state_with_snapshot_batch(touched_paths, create_snapshot, unix_ts())
            .await?;

        Ok(PathMutationResult::Applied)
    }

    async fn restore_snapshot_object_path_inner(
        &mut self,
        snapshot_state: &SnapshotObjectState,
        source_path: &str,
        target_path: &str,
        create_snapshot: bool,
        overwrite: bool,
    ) -> Result<PathMutationResult> {
        let Some(source) = self
            .snapshot_restore_source(snapshot_state, source_path)
            .await?
        else {
            return Ok(PathMutationResult::SourceMissing);
        };

        self.restore_object_path_from_source(
            source,
            source_path,
            target_path,
            create_snapshot,
            overwrite,
        )
        .await
    }

    async fn snapshot_restore_source(
        &self,
        snapshot_state: &SnapshotObjectState,
        source_path: &str,
    ) -> Result<Option<SnapshotRestoreSource>> {
        let Some(manifest_hash) = snapshot_state.objects.get(source_path).cloned() else {
            return Ok(None);
        };

        let Some(source_object_id) = snapshot_state.object_ids.get(source_path).cloned() else {
            return Ok(Some(SnapshotRestoreSource {
                manifest_hash,
                object_id: None,
                version_id: None,
                state: VersionConsistencyState::Confirmed,
            }));
        };

        let Some(index) = self
            .load_version_index_by_object_id(&source_object_id)
            .await?
        else {
            return Ok(Some(SnapshotRestoreSource {
                manifest_hash,
                object_id: Some(source_object_id),
                version_id: None,
                state: VersionConsistencyState::Confirmed,
            }));
        };

        let matching_record = snapshot_version_record_for_manifest(
            &index,
            &manifest_hash,
            snapshot_state.created_at_unix,
        )
        .or_else(|| {
            index
                .versions
                .values()
                .filter(|record| record.manifest_hash == manifest_hash)
                .max_by(|left, right| {
                    left.created_at_unix
                        .cmp(&right.created_at_unix)
                        .then_with(|| left.version_id.cmp(&right.version_id))
                })
        });

        Ok(Some(SnapshotRestoreSource {
            manifest_hash,
            object_id: Some(source_object_id),
            version_id: matching_record.map(|record| record.version_id.clone()),
            state: matching_record
                .map(|record| record.state.clone())
                .unwrap_or(VersionConsistencyState::Confirmed),
        }))
    }

    async fn version_restore_source(
        &self,
        source_path: &str,
        version_id: &str,
    ) -> Result<Option<SnapshotRestoreSource>> {
        let Some(source_object_id) = self
            .resolve_object_id_for_key_version(source_path, version_id)
            .await?
        else {
            return Ok(None);
        };

        let Some(index) = self
            .load_version_index_by_object_id(&source_object_id)
            .await?
        else {
            return Ok(None);
        };

        let Some(record) = index.versions.get(version_id) else {
            return Ok(None);
        };

        if record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
            return Ok(None);
        }

        Ok(Some(SnapshotRestoreSource {
            manifest_hash: record.manifest_hash.clone(),
            object_id: Some(source_object_id),
            version_id: Some(record.version_id.clone()),
            state: record.state.clone(),
        }))
    }

    pub async fn restore_version_path(
        &mut self,
        source_path: &str,
        version_id: &str,
        target_path: &str,
        overwrite: bool,
    ) -> Result<PathMutationResult> {
        let Some(source) = self.version_restore_source(source_path, version_id).await? else {
            return Ok(PathMutationResult::SourceMissing);
        };

        self.restore_object_path_from_source(source, source_path, target_path, true, overwrite)
            .await
    }

    async fn resolve_object_id_for_key_history(&self, key: &str) -> Result<Option<String>> {
        if let Some(object_id) = self.object_id_for_key(key).await? {
            return Ok(Some(object_id));
        }

        for index in self.load_all_version_indexes().await? {
            if self.resolve_key_for_version_index(&index).await?.as_deref() == Some(key) {
                return Ok(Some(index.object_id));
            }
        }

        Ok(None)
    }

    async fn resolve_object_id_for_key_version(
        &self,
        key: &str,
        version_id: &str,
    ) -> Result<Option<String>> {
        if let Some(object_id) = self.object_id_for_key(key).await?
            && let Some(index) = self.load_version_index_by_object_id(&object_id).await?
            && index.versions.contains_key(version_id)
        {
            return Ok(Some(object_id));
        }

        for index in self.load_all_version_indexes().await? {
            let Some(record) = index.versions.get(version_id) else {
                continue;
            };

            if record.logical_path.as_deref() == Some(key)
                || self
                    .resolve_key_for_version_record(&index, record)
                    .await?
                    .as_deref()
                    == Some(key)
            {
                return Ok(Some(index.object_id));
            }
        }

        Ok(None)
    }

    async fn build_delete_recreate_loop_cleanup_candidate(
        &self,
        index: FileVersionIndex,
    ) -> Result<DeleteRecreateLoopCleanupCandidateOutcome> {
        if index.versions.is_empty() {
            return Ok(DeleteRecreateLoopCleanupCandidateOutcome::NoDeleteRecreateLoop);
        }

        let mut normalized_versions = Vec::with_capacity(index.versions.len());
        let mut distinct_paths = BTreeSet::<String>::new();
        let mut has_live_version = false;
        let mut has_tombstone_version = false;

        let mut version_ids = index.versions.keys().cloned().collect::<Vec<_>>();
        version_ids.sort();

        for version_id in version_ids {
            let Some(record) = index.versions.get(&version_id) else {
                continue;
            };
            let Some(resolved_path) = self.resolve_key_for_version_record(&index, record).await?
            else {
                return Ok(DeleteRecreateLoopCleanupCandidateOutcome::UnresolvedPath);
            };
            distinct_paths.insert(resolved_path.clone());
            if distinct_paths.len() > 1 {
                return Ok(DeleteRecreateLoopCleanupCandidateOutcome::MultiplePaths);
            }

            if record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
                has_tombstone_version = true;
            } else {
                has_live_version = true;
            }

            normalized_versions.push(DeleteRecreateLoopNormalizedVersionRecord {
                version_id: record.version_id.clone(),
                manifest_hash: record.manifest_hash.clone(),
                logical_path: resolved_path,
                parent_version_ids: record.parent_version_ids.clone(),
                state: record.state.clone(),
                copied_from_object_id: record.copied_from_object_id.clone(),
                copied_from_version_id: record.copied_from_version_id.clone(),
                copied_from_path: record.copied_from_path.clone(),
            });
        }

        if !has_live_version || !has_tombstone_version {
            return Ok(DeleteRecreateLoopCleanupCandidateOutcome::NoDeleteRecreateLoop);
        }

        let Some(key) = distinct_paths.into_iter().next() else {
            return Ok(DeleteRecreateLoopCleanupCandidateOutcome::UnresolvedPath);
        };
        let mut head_version_ids = index.head_version_ids.clone();
        head_version_ids.sort();

        Ok(DeleteRecreateLoopCleanupCandidateOutcome::Candidate(
            Box::new(DeleteRecreateLoopCleanupCandidate {
                key: key.clone(),
                object_id: index.object_id.clone(),
                bound_current: self.object_id_for_key(&key).await?.as_deref()
                    == Some(index.object_id.as_str()),
                signature: DeleteRecreateLoopNormalizedIndexSignature {
                    preferred_head_version_id: index.preferred_head_version_id.clone(),
                    head_version_ids,
                    versions: normalized_versions,
                },
                index,
            }),
        ))
    }

    async fn choose_replication_bundle_object_id(
        &self,
        bundle: &ReplicationExportBundle,
        key: &str,
        resolved_version_id: &str,
        created_at_unix: u64,
    ) -> Result<ReplicationImportLineageChoice> {
        if bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH {
            if let Some(object_id) = bundle.object_id.clone() {
                return Ok(ReplicationImportLineageChoice::existing(object_id));
            }
            if let Some(version_id) = bundle.version_id.as_deref()
                && let Some(object_id) = self
                    .resolve_object_id_for_key_version(key, version_id)
                    .await?
            {
                return Ok(ReplicationImportLineageChoice::existing(object_id));
            }
            if let Some(object_id) = self.resolve_object_id_for_key_history(key).await? {
                return Ok(ReplicationImportLineageChoice::existing(object_id));
            }
            return Ok(ReplicationImportLineageChoice::existing(
                generate_object_id(),
            ));
        }

        if let Some(source_object_id) = bundle.object_id.clone() {
            if !bundle.selected_is_preferred_head {
                if let Some(version_id) = bundle.version_id.as_deref()
                    && let Some(object_id) = self
                        .resolve_object_id_for_key_version(key, version_id)
                        .await?
                {
                    return Ok(ReplicationImportLineageChoice::existing(object_id));
                }

                if let Some(object_id) = self.object_id_for_key(key).await? {
                    return Ok(ReplicationImportLineageChoice::existing(object_id));
                }

                if let Some(object_id) = self.resolve_object_id_for_key_history(key).await? {
                    return Ok(ReplicationImportLineageChoice::existing(object_id));
                }

                return Ok(ReplicationImportLineageChoice::existing(source_object_id));
            }

            if let Some(index) = self
                .load_version_index_by_object_id(&source_object_id)
                .await?
            {
                let preferred_head = index
                    .preferred_head_version_id
                    .as_ref()
                    .and_then(|version_id| index.versions.get(version_id));
                let preferred_is_tombstone = preferred_head
                    .map(|record| record.manifest_hash == TOMBSTONE_MANIFEST_HASH)
                    .unwrap_or(false);
                if preferred_is_tombstone
                    && index.preferred_head_version_id.as_deref() != Some(resolved_version_id)
                {
                    return Ok(ReplicationImportLineageChoice::conflict_recreated(
                        generate_object_id(),
                    ));
                }
            }

            return Ok(ReplicationImportLineageChoice::existing(source_object_id));
        }

        if let Some(current_object_id) = self.object_id_for_key(key).await?
            && let Some(index) = self
                .load_version_index_by_object_id(&current_object_id)
                .await?
            && let Some(existing) = index.versions.get(resolved_version_id)
        {
            let expected = FileVersionRecord {
                version_id: resolved_version_id.to_string(),
                object_id: current_object_id.clone(),
                manifest_hash: bundle.manifest_hash.clone(),
                logical_path: Some(key.to_string()),
                parent_version_ids: bundle.parent_version_ids.clone(),
                state: bundle.state.clone(),
                created_at_unix,
                copied_from_object_id: bundle.copied_from_object_id.clone(),
                copied_from_version_id: bundle.copied_from_version_id.clone(),
                copied_from_path: bundle.copied_from_path.clone(),
            };
            if replication_bundle_record_matches(existing, &expected) {
                return Ok(ReplicationImportLineageChoice::existing(current_object_id));
            }
        }

        if let Some(version_id) = bundle.version_id.as_deref()
            && let Some(object_id) = self
                .resolve_object_id_for_key_version(key, version_id)
                .await?
        {
            return Ok(ReplicationImportLineageChoice::existing(object_id));
        }

        if let Some(object_id) = self.object_id_for_key(key).await? {
            return Ok(ReplicationImportLineageChoice::existing(object_id));
        }

        if !bundle.selected_is_preferred_head
            && let Some(object_id) = self.resolve_object_id_for_key_history(key).await?
        {
            return Ok(ReplicationImportLineageChoice::existing(object_id));
        }

        Ok(ReplicationImportLineageChoice::existing(
            generate_object_id(),
        ))
    }

    async fn prune_conflicting_replication_bundle_versions(
        &mut self,
        key: &str,
        keep_record: &FileVersionRecord,
    ) -> Result<()> {
        let mut indexes = self.load_all_version_indexes().await?;

        for mut index in indexes.drain(..) {
            let Some(existing) = index.versions.get(&keep_record.version_id).cloned() else {
                continue;
            };
            if existing.logical_path.as_deref() != Some(key) {
                continue;
            }
            if index.object_id == keep_record.object_id
                && replication_bundle_record_matches(&existing, keep_record)
            {
                continue;
            }

            index.versions.remove(&keep_record.version_id);
            index.head_version_ids = recompute_head_version_ids(&index);
            index.preferred_head_version_id = choose_preferred_head(&index);

            if index.versions.is_empty() {
                self.delete_version_index_by_object_id(&index.object_id)
                    .await?;
                if self.object_id_for_key(key).await?.as_deref() == Some(index.object_id.as_str()) {
                    self.remove_current_object(key).await?;
                }
                continue;
            }

            self.persist_version_index_by_object_id(&index.object_id, &index)
                .await?;
            self.sync_current_state_for_key_from_index(key, &index)
                .await?;
        }

        Ok(())
    }

    async fn replica_tombstone_supersedes_current_key(
        &self,
        key: &str,
        current_object_id: &str,
        bundle: &ReplicationExportBundle,
    ) -> Result<bool> {
        let Some(index) = self
            .load_version_index_by_object_id(current_object_id)
            .await?
        else {
            return Ok(false);
        };
        let Some(current_head_id) = index.preferred_head_version_id.as_ref() else {
            return Ok(false);
        };
        let Some(current_record) = index.versions.get(current_head_id) else {
            return Ok(false);
        };
        if current_record.logical_path.as_deref() != Some(key)
            || current_record.manifest_hash == TOMBSTONE_MANIFEST_HASH
        {
            return Ok(false);
        }

        let tombstone_order = replica_version_order_key(
            bundle.version_id.as_deref(),
            bundle.created_at_unix.unwrap_or_default(),
        );
        let current_order = replica_version_order_key(
            Some(current_record.version_id.as_str()),
            current_record.created_at_unix,
        );

        Ok(tombstone_order > current_order)
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

            match self.load_manifest_by_hash(&record.manifest_hash).await {
                Ok(Some(manifest)) => return Ok(Some(manifest.key)),
                Ok(None) => continue,
                Err(err) => {
                    warn!(
                        manifest_hash = %record.manifest_hash,
                        object_id = %index.object_id,
                        version_id = %record.version_id,
                        error = %err,
                        "manifest unreadable or invalid while resolving version key; skipping record"
                    );
                }
            }
        }

        Ok(None)
    }

    async fn resolve_key_for_version_record(
        &self,
        index: &FileVersionIndex,
        record: &FileVersionRecord,
    ) -> Result<Option<String>> {
        if let Some(logical_path) = record.logical_path.clone() {
            return Ok(Some(logical_path));
        }

        if record.manifest_hash != TOMBSTONE_MANIFEST_HASH {
            match self.load_manifest_by_hash(&record.manifest_hash).await {
                Ok(Some(manifest)) => return Ok(Some(manifest.key)),
                Ok(None) => {}
                Err(err) => {
                    warn!(
                        manifest_hash = %record.manifest_hash,
                        object_id = %index.object_id,
                        version_id = %record.version_id,
                        error = %err,
                        "manifest unreadable or invalid while resolving version key; falling back to index lookup"
                    );
                }
            }
        }

        self.resolve_key_for_version_index(index).await
    }

    async fn maybe_rotate_snapshot_batch(
        &mut self,
        touched_paths: &BTreeSet<String>,
    ) -> Result<()> {
        if touched_paths.is_empty() {
            return Ok(());
        }

        let Some(batch) = self.snapshot_batch.as_ref() else {
            return Ok(());
        };

        let has_overlap = touched_paths
            .iter()
            .any(|path| batch.dirty_paths.contains(path.as_str()));
        let exceeds_time_window = unix_ts().saturating_sub(batch.started_at_unix)
            > SNAPSHOT_HISTORY_MAX_BATCH_WINDOW_SECS;

        if has_overlap || exceeds_time_window {
            self.snapshot_batch = None;
            self.metadata_store
                .persist_snapshot_batch_state(None)
                .await?;
        }

        Ok(())
    }

    async fn record_snapshot_batch(
        &mut self,
        changed_paths: BTreeSet<String>,
        changed_at_unix: u64,
    ) -> Result<String> {
        if changed_paths.is_empty() {
            bail!("snapshot batch requires at least one changed path");
        }

        let (snapshot_id, last_changed_at_unix) = {
            let batch = self
                .snapshot_batch
                .get_or_insert_with(|| ActiveSnapshotBatch {
                    snapshot_id: format!("snap-batch-{}", Uuid::now_v7()),
                    started_at_unix: changed_at_unix,
                    last_changed_at_unix: changed_at_unix,
                    dirty_paths: BTreeSet::new(),
                });
            batch.last_changed_at_unix = changed_at_unix;
            batch.dirty_paths.extend(changed_paths);
            (batch.snapshot_id.clone(), batch.last_changed_at_unix)
        };

        let current_state = self.metadata_store.load_current_state().await?;
        let manifest = SnapshotManifest {
            id: snapshot_id.clone(),
            created_at_unix: last_changed_at_unix,
            objects: current_state.objects,
            object_ids: current_state.object_ids,
        };

        self.metadata_store
            .persist_snapshot_manifest(&manifest)
            .await?;
        self.metadata_store
            .persist_snapshot_batch_state(self.snapshot_batch.as_ref())
            .await?;

        Ok(snapshot_id)
    }

    async fn persist_current_state_with_snapshot_batch(
        &mut self,
        changed_paths: BTreeSet<String>,
        create_snapshot: bool,
        changed_at_unix: u64,
    ) -> Result<Option<String>> {
        if !create_snapshot || changed_paths.is_empty() {
            return Ok(None);
        }

        Ok(Some(
            self.record_snapshot_batch(changed_paths, changed_at_unix)
                .await?,
        ))
    }

    async fn create_snapshot(&mut self) -> Result<String> {
        let created_at_unix = unix_ts();
        let current_state = self.metadata_store.load_current_state().await?;
        let object_map_payload = serde_json::to_vec(&(
            current_state.objects.clone(),
            current_state.object_ids.clone(),
        ))?;
        let state_hash = hash_hex(&object_map_payload);
        let snapshot_id = format!("snap-{}-{}", unix_ts_nanos(), &state_hash[..12]);

        let manifest = SnapshotManifest {
            id: snapshot_id.clone(),
            created_at_unix,
            objects: current_state.objects,
            object_ids: current_state.object_ids,
        };

        self.metadata_store
            .persist_snapshot_manifest(&manifest)
            .await?;
        if self.snapshot_batch.is_some() {
            self.snapshot_batch = None;
            self.metadata_store
                .persist_snapshot_batch_state(None)
                .await?;
        }

        Ok(snapshot_id)
    }

    #[cfg(test)]
    fn active_snapshot_batch_id_for_test(&self) -> Option<String> {
        self.snapshot_batch
            .as_ref()
            .map(|batch| batch.snapshot_id.clone())
    }

    #[cfg(test)]
    async fn set_snapshot_batch_started_at_unix_for_test(
        &mut self,
        started_at_unix: u64,
    ) -> Result<()> {
        if let Some(batch) = self.snapshot_batch.as_mut() {
            batch.started_at_unix = started_at_unix;
            self.metadata_store
                .persist_snapshot_batch_state(self.snapshot_batch.as_ref())
                .await?;
        }
        Ok(())
    }

    async fn read_snapshot(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
        self.load_snapshot_manifest(snapshot_id).await
    }

    async fn collect_referenced_manifest_hashes(&self) -> Result<HashSet<String>> {
        let mut referenced = HashSet::<String>::new();

        for manifest_hash in self
            .metadata_store
            .load_current_state()
            .await?
            .objects
            .values()
        {
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

    /// Lists manifest hashes present in the manifest store without parsing their
    /// content, so GC's orphan scan doesn't have to hold every manifest's bytes in
    /// memory just to enumerate hashes.
    async fn list_manifest_hashes(&self) -> Result<Vec<String>> {
        let mut hashes = Vec::<String>::new();
        let mut entries = fs::read_dir(&self.manifests_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            hashes.push(file_stem.to_string());
        }

        Ok(hashes)
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

    async fn delete_snapshots_by_id(&self, snapshot_ids: &[String]) -> Result<()> {
        self.metadata_store
            .delete_snapshots_by_id(snapshot_ids)
            .await
    }

    async fn vacuum_metadata_store(&self) -> Result<bool> {
        self.metadata_store.vacuum_metadata_store().await
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

impl MetadataDbDistributionLoader {
    pub(crate) async fn load_with_progress(
        &self,
        progress: Option<MetadataDbLogicalProgressCallback>,
    ) -> Result<MetadataDbLogicalDistribution> {
        let mut tables = self
            .metadata_store
            .load_metadata_db_logical_breakdown(progress)
            .await?;
        tables.sort_by(|left, right| {
            right
                .tracked_value_bytes
                .cmp(&left.tracked_value_bytes)
                .then_with(|| right.row_count.cmp(&left.row_count))
                .then_with(|| left.table.cmp(&right.table))
        });

        Ok(MetadataDbLogicalDistribution {
            backend: self.metadata_backend_kind,
            generated_at_unix: unix_ts(),
            total_row_count: tables.iter().map(|table| table.row_count).sum(),
            total_tracked_value_bytes: tables.iter().map(|table| table.tracked_value_bytes).sum(),
            tables,
        })
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

enum DeleteRecreateLoopCleanupCandidateOutcome {
    Candidate(Box<DeleteRecreateLoopCleanupCandidate>),
    UnresolvedPath,
    MultiplePaths,
    NoDeleteRecreateLoop,
}

struct DeleteRecreateLoopCleanupCandidate {
    key: String,
    object_id: String,
    bound_current: bool,
    signature: DeleteRecreateLoopNormalizedIndexSignature,
    index: FileVersionIndex,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DeleteRecreateLoopNormalizedIndexSignature {
    preferred_head_version_id: Option<String>,
    head_version_ids: Vec<String>,
    versions: Vec<DeleteRecreateLoopNormalizedVersionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DeleteRecreateLoopNormalizedVersionRecord {
    version_id: String,
    manifest_hash: String,
    logical_path: String,
    parent_version_ids: Vec<String>,
    state: VersionConsistencyState,
    copied_from_object_id: Option<String>,
    copied_from_version_id: Option<String>,
    copied_from_path: Option<String>,
}

fn select_delete_recreate_loop_cleanup_canonical(
    candidates: &[DeleteRecreateLoopCleanupCandidate],
) -> usize {
    candidates
        .iter()
        .enumerate()
        .max_by(|(left_idx, left), (right_idx, right)| {
            left.bound_current
                .cmp(&right.bound_current)
                .then_with(|| left.index.versions.len().cmp(&right.index.versions.len()))
                .then_with(|| right.object_id.cmp(&left.object_id))
                .then_with(|| right_idx.cmp(left_idx))
        })
        .map(|(idx, _)| idx)
        .unwrap_or(0)
}

fn replication_bundle_record_matches(
    existing: &FileVersionRecord,
    expected: &FileVersionRecord,
) -> bool {
    existing.version_id == expected.version_id
        && existing.object_id == expected.object_id
        && existing.manifest_hash == expected.manifest_hash
        && existing.logical_path == expected.logical_path
        && existing.parent_version_ids == expected.parent_version_ids
        && existing.state == expected.state
        && existing.created_at_unix == expected.created_at_unix
        && existing.copied_from_object_id == expected.copied_from_object_id
        && existing.copied_from_version_id == expected.copied_from_version_id
        && existing.copied_from_path == expected.copied_from_path
}

struct ReplicationImportLineageChoice {
    object_id: String,
    conflict_recreated: bool,
}

impl ReplicationImportLineageChoice {
    fn existing(object_id: String) -> Self {
        Self {
            object_id,
            conflict_recreated: false,
        }
    }

    fn conflict_recreated(object_id: String) -> Self {
        Self {
            object_id,
            conflict_recreated: true,
        }
    }
}

fn replica_version_order_key(version_id: Option<&str>, created_at_unix: u64) -> (u64, u128) {
    let version_nanos = version_id
        .and_then(parse_replica_version_nanos)
        .unwrap_or_else(|| u128::from(created_at_unix).saturating_mul(1_000_000_000));
    (created_at_unix, version_nanos)
}

fn parse_replica_version_nanos(version_id: &str) -> Option<u128> {
    let (_, suffix) = version_id.split_once('-')?;
    let timestamp = suffix.split('-').next()?;
    timestamp.parse::<u128>().ok()
}

pub(super) fn content_fingerprint_from_manifest(manifest: &ObjectManifest) -> String {
    content_fingerprint_from_chunk_refs(
        manifest.total_size_bytes as u64,
        manifest
            .chunks
            .iter()
            .map(|chunk| (chunk.hash.as_str(), chunk.size_bytes as u64)),
    )
}

async fn file_size_bytes(path: &Path) -> Result<u64> {
    match fs::metadata(path).await {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err).with_context(|| format!("failed to stat {}", path.display())),
    }
}

async fn directory_size_bytes(root: &Path) -> Result<u64> {
    Ok(directory_file_stats(root).await?.1)
}

async fn directory_file_stats(root: &Path) -> Result<(usize, u64)> {
    match fs::metadata(root).await {
        Ok(metadata) if metadata.is_file() => return Ok((1, metadata.len())),
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to stat {}", root.display()));
        }
    }

    let mut files = 0usize;
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
                files += 1;
                total = total.saturating_add(metadata.len());
            }
        }
    }

    Ok((files, total))
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

fn snapshot_version_record_for_manifest<'a>(
    index: &'a FileVersionIndex,
    manifest_hash: &str,
    max_created_at_unix: u64,
) -> Option<&'a FileVersionRecord> {
    index
        .versions
        .values()
        .filter(|record| record.manifest_hash == manifest_hash)
        .filter(|record| record.created_at_unix <= max_created_at_unix)
        .max_by(|left, right| {
            left.created_at_unix
                .cmp(&right.created_at_unix)
                .then_with(|| left.version_id.cmp(&right.version_id))
        })
}

fn snapshot_changed_paths(
    previous: Option<&SnapshotManifest>,
    current: &SnapshotManifest,
) -> BTreeSet<String> {
    let mut candidate_paths = BTreeSet::new();

    if let Some(previous) = previous {
        candidate_paths.extend(previous.objects.keys().cloned());
        candidate_paths.extend(previous.object_ids.keys().cloned());
    }
    candidate_paths.extend(current.objects.keys().cloned());
    candidate_paths.extend(current.object_ids.keys().cloned());

    candidate_paths
        .into_iter()
        .filter(|path| {
            snapshot_path_binding(previous, path) != snapshot_path_binding(Some(current), path)
        })
        .collect()
}

fn snapshot_path_binding<'a>(
    snapshot: Option<&'a SnapshotManifest>,
    path: &str,
) -> (Option<&'a str>, Option<&'a str>) {
    let manifest_hash = snapshot
        .and_then(|snapshot| snapshot.objects.get(path))
        .map(String::as_str);
    let object_id = snapshot
        .and_then(|snapshot| snapshot.object_ids.get(path))
        .map(String::as_str);
    (manifest_hash, object_id)
}

fn rank_state(state: &VersionConsistencyState) -> u8 {
    match state {
        VersionConsistencyState::Confirmed => 2,
        VersionConsistencyState::Provisional => 1,
    }
}

enum LocalChunkIntegrity {
    Valid,
    Missing,
    SizeMismatch { actual_size_bytes: u64 },
    HashMismatch { actual_hash: String },
}

async fn validate_local_chunk_integrity(
    chunks_dir: &Path,
    hash: &str,
    expected_size_bytes: usize,
) -> Result<LocalChunkIntegrity> {
    let chunk_path = chunk_path_for_hash(chunks_dir, hash)?;
    let payload = match fs::read(&chunk_path).await {
        Ok(payload) => payload,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LocalChunkIntegrity::Missing);
        }
        Err(err) => return Err(err.into()),
    };

    if payload.len() != expected_size_bytes {
        return Ok(LocalChunkIntegrity::SizeMismatch {
            actual_size_bytes: payload.len() as u64,
        });
    }

    let actual_hash = hash_hex(&payload);
    if actual_hash != hash {
        return Ok(LocalChunkIntegrity::HashMismatch { actual_hash });
    }

    Ok(LocalChunkIntegrity::Valid)
}

pub(super) fn chunk_path_for_hash(chunks_dir: &Path, hash: &str) -> anyhow::Result<PathBuf> {
    if hash.len() != blake3::OUT_LEN * 2 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("invalid chunk hash: {hash}");
    }
    let prefix = &hash[..2];
    Ok(chunks_dir.join(prefix).join(hash))
}

pub(super) fn hash_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

pub(super) fn unix_ts() -> u64 {
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

pub(super) async fn write_atomic(path: &Path, payload: &[u8]) -> Result<()> {
    write_atomic_impl(path, payload, false).await
}

async fn write_atomic_overwrite(path: &Path, payload: &[u8]) -> Result<()> {
    write_atomic_impl(path, payload, true).await
}

async fn write_atomic_impl(path: &Path, payload: &[u8], overwrite_existing: bool) -> Result<()> {
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
    if overwrite_existing {
        match fs::metadata(path).await {
            Ok(metadata) if metadata.is_dir() => {
                fs::remove_dir_all(path).await?;
            }
            Ok(_) => {
                fs::remove_file(path).await?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
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
#[path = "../storage_tests.rs"]
mod tests;
