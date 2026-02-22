use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
use common::NodeId;
use serde::{Deserialize, Serialize};
use tokio::fs;

const CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkRef {
    hash: String,
    size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectManifest {
    key: String,
    total_size_bytes: usize,
    created_at_unix: u64,
    chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotManifest {
    id: String,
    created_at_unix: u64,
    objects: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CurrentState {
    objects: HashMap<String, String>,
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
    key: String,
    manifest_hash: String,
    parent_version_ids: Vec<String>,
    state: VersionConsistencyState,
    created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileVersionIndex {
    key: String,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionGraphSummary {
    pub key: String,
    pub preferred_head_version_id: Option<String>,
    pub preferred_head_reason: Option<PreferredHeadReason>,
    pub head_version_ids: Vec<String>,
    pub versions: Vec<VersionRecordSummary>,
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
pub struct ReplicationManifestPayload {
    pub key: String,
    pub total_size_bytes: usize,
    pub created_at_unix: u64,
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
    pub state: VersionConsistencyState,
    pub new_chunks: usize,
    pub dedup_reused_chunks: usize,
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
    internal_node_tokens_path: PathBuf,
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
        let internal_node_tokens_path = state_dir.join("internal_node_tokens.json");

        fs::create_dir_all(&chunks_dir).await?;
        fs::create_dir_all(&manifests_dir).await?;
        fs::create_dir_all(&snapshots_dir).await?;
        fs::create_dir_all(&versions_dir).await?;
        fs::create_dir_all(&reconcile_markers_dir).await?;
        fs::create_dir_all(&state_dir).await?;

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
            internal_node_tokens_path,
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

    pub async fn load_internal_node_tokens(&self) -> Result<HashMap<NodeId, String>> {
        if !fs::try_exists(&self.internal_node_tokens_path).await? {
            return Ok(HashMap::new());
        }

        let payload = fs::read(&self.internal_node_tokens_path).await?;
        let tokens =
            serde_json::from_slice::<HashMap<NodeId, String>>(&payload).with_context(|| {
                format!(
                    "invalid internal node tokens state: {}",
                    self.internal_node_tokens_path.display()
                )
            })?;

        Ok(tokens)
    }

    pub async fn persist_internal_node_tokens(
        &self,
        tokens: &HashMap<NodeId, String>,
    ) -> Result<()> {
        let payload = serde_json::to_vec_pretty(tokens)?;
        write_atomic(&self.internal_node_tokens_path, &payload).await
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

    pub async fn snapshot_keys(&self, snapshot_id: &str) -> Result<Option<Vec<String>>> {
        let snapshot_path = self.snapshots_dir.join(format!("{snapshot_id}.json"));
        if !fs::try_exists(&snapshot_path).await? {
            return Ok(None);
        }

        let payload = fs::read(&snapshot_path).await?;
        let manifest = serde_json::from_slice::<SnapshotManifest>(&payload)
            .with_context(|| format!("invalid snapshot manifest {}", snapshot_path.display()))?;

        let mut keys: Vec<String> = manifest.objects.keys().cloned().collect();
        keys.sort();
        Ok(Some(keys))
    }

    pub async fn list_replication_subjects(&self) -> Result<Vec<String>> {
        let mut subjects: HashSet<String> = self.current_state.objects.keys().cloned().collect();

        let mut entries = fs::read_dir(&self.versions_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let payload = fs::read(&path).await?;
            let index = serde_json::from_slice::<FileVersionIndex>(&payload)
                .with_context(|| format!("invalid version index {}", path.display()))?;

            for head_version_id in &index.head_version_ids {
                subjects.insert(format!("{}@{}", index.key, head_version_id));
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
            created_at_unix: unix_ts(),
            chunks: chunk_refs,
        };

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let manifest_hash = hash_hex(&manifest_bytes);
        let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));

        if !fs::try_exists(&manifest_path).await? {
            write_atomic(&manifest_path, &manifest_bytes).await?;
        }

        let mut index = self
            .load_version_index(key)
            .await?
            .unwrap_or_else(|| empty_version_index(key));

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
            .unwrap_or_else(|| format!("ver-{}-{}", unix_ts_nanos(), &manifest_hash[..12]));

        if let Some(existing) = index.versions.get(&version_id) {
            if existing.manifest_hash != manifest_hash {
                bail!(
                    "version id collision for key={key} version_id={version_id}: different manifest"
                );
            }

            self.sync_current_state_for_key_from_index(key, &index)?;
            self.persist_current_state().await?;

            let snapshot_id = if options.create_snapshot {
                self.create_snapshot().await?
            } else {
                format!("snap-skipped-{version_id}")
            };

            return Ok(PutResult {
                snapshot_id,
                version_id,
                state: existing.state.clone(),
                new_chunks,
                dedup_reused_chunks,
            });
        }

        let record = FileVersionRecord {
            version_id: version_id.clone(),
            key: key.to_string(),
            manifest_hash: manifest_hash.clone(),
            parent_version_ids: parent_version_ids.clone(),
            state: options.state.clone(),
            created_at_unix: unix_ts(),
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

        self.persist_version_index(key, &index).await?;
        self.sync_current_state_for_key_from_index(key, &index)?;
        self.persist_current_state().await?;

        let snapshot_id = if options.create_snapshot {
            self.create_snapshot().await?
        } else {
            format!("snap-skipped-{version_id}")
        };

        Ok(PutResult {
            snapshot_id,
            version_id,
            state: options.state,
            new_chunks,
            dedup_reused_chunks,
        })
    }

    pub async fn commit_version(&mut self, key: &str, version_id: &str) -> Result<bool> {
        let mut index = match self.load_version_index(key).await? {
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

        self.persist_version_index(key, &index).await?;
        self.sync_current_state_for_key_from_index(key, &index)?;
        self.persist_current_state().await?;
        self.create_snapshot().await?;

        Ok(true)
    }

    pub async fn list_versions(&self, key: &str) -> Result<Option<VersionGraphSummary>> {
        let Some(index) = self.load_version_index(key).await? else {
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
            })
            .collect();

        versions.sort_by(|a, b| {
            b.created_at_unix
                .cmp(&a.created_at_unix)
                .then_with(|| b.version_id.cmp(&a.version_id))
        });

        let preferred = choose_preferred_head_with_reason(&index);

        Ok(Some(VersionGraphSummary {
            key: index.key,
            preferred_head_version_id: preferred.as_ref().map(|(id, _)| id.clone()),
            preferred_head_reason: preferred.map(|(_, reason)| reason),
            head_version_ids: index.head_version_ids,
            versions,
        }))
    }

    pub async fn has_manifest_for_key(&self, key: &str, manifest_hash: &str) -> Result<bool> {
        let Some(index) = self.load_version_index(key).await? else {
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
        let (selected_version_id, state, manifest_hash) = if let Some(version_id) = version_id {
            let Some(index) = self.load_version_index(key).await? else {
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
            match self.load_version_index(key).await? {
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

        if manifest.key != key {
            bail!(
                "manifest key mismatch for replication export: expected={key} actual={}",
                manifest.key
            );
        }

        Ok(Some(ReplicationExportBundle {
            key: key.to_string(),
            version_id: selected_version_id,
            state,
            manifest_hash,
            manifest_bytes,
            manifest: ReplicationManifestPayload {
                key: manifest.key,
                total_size_bytes: manifest.total_size_bytes,
                created_at_unix: manifest.created_at_unix,
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

        let mut index = self
            .load_version_index(key)
            .await?
            .unwrap_or_else(|| empty_version_index(key));

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
            key: key.to_string(),
            manifest_hash: manifest_hash.to_string(),
            parent_version_ids: Vec::new(),
            state,
            created_at_unix: unix_ts(),
        };

        index.versions.insert(resolved_version_id.clone(), record);

        let mut heads: HashSet<String> = index.head_version_ids.into_iter().collect();
        heads.insert(resolved_version_id.clone());

        index.head_version_ids = heads.into_iter().collect();
        index.head_version_ids.sort();
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index(key, &index).await?;
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

        let Some(mut index) = self.load_version_index(key).await? else {
            return Ok(false);
        };

        if index.versions.remove(version_id).is_none() {
            return Ok(false);
        }

        index.head_version_ids = recompute_head_version_ids(&index);
        index.preferred_head_version_id = choose_preferred_head(&index);

        self.persist_version_index(key, &index).await?;
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

                output.push(ReconcileVersionEntry {
                    key: record.key.clone(),
                    version_id: record.version_id.clone(),
                    manifest_hash: record.manifest_hash.clone(),
                    parent_version_ids: record.parent_version_ids.clone(),
                    state: record.state.clone(),
                    created_at_unix: record.created_at_unix,
                });
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

    pub async fn get_object(
        &self,
        key: &str,
        snapshot_id: Option<&str>,
        version_id: Option<&str>,
        read_mode: ObjectReadMode,
    ) -> std::result::Result<Bytes, StoreReadError> {
        let manifest_hash = if let Some(version_id) = version_id {
            let index = self
                .load_version_index(key)
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
            let index = self
                .load_version_index(key)
                .await
                .map_err(StoreReadError::Internal)?;

            match index {
                Some(index) => manifest_hash_for_read_mode(&index, read_mode),
                None => self.current_state.objects.get(key).cloned(),
            }
        }
        .ok_or(StoreReadError::NotFound)?;

        let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));

        if !fs::try_exists(&manifest_path)
            .await
            .map_err(|err| StoreReadError::Internal(err.into()))?
        {
            return Err(StoreReadError::Corrupt(format!(
                "manifest missing for hash={manifest_hash}"
            )));
        }

        let manifest_bytes = fs::read(&manifest_path)
            .await
            .map_err(|err| StoreReadError::Internal(err.into()))?;

        let manifest = serde_json::from_slice::<ObjectManifest>(&manifest_bytes)
            .with_context(|| format!("invalid manifest {}", manifest_path.display()))
            .map_err(StoreReadError::Internal)?;

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

        for (manifest_hash, manifest) in &all_manifests {
            if referenced_manifests.contains(manifest_hash) {
                continue;
            }

            let age_secs = now.saturating_sub(manifest.created_at_unix);
            if age_secs < retention_secs {
                retained_manifests.insert(manifest_hash.clone());
                skipped_recent_manifests += 1;
                continue;
            }

            if dry_run {
                continue;
            }

            let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));
            if fs::try_exists(&manifest_path).await? {
                fs::remove_file(&manifest_path).await?;
                deleted_manifests += 1;
            }
        }

        let mut protected_chunks = HashSet::<String>::new();
        for manifest_hash in &retained_manifests {
            if let Some(manifest) = all_manifests.get(manifest_hash) {
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

    async fn load_version_index(&self, key: &str) -> Result<Option<FileVersionIndex>> {
        let path = self.version_index_path(key);

        if !fs::try_exists(&path).await? {
            return Ok(None);
        }

        let payload = fs::read(&path).await?;
        let index = serde_json::from_slice::<FileVersionIndex>(&payload)
            .with_context(|| format!("invalid version index {}", path.display()))?;

        Ok(Some(index))
    }

    async fn persist_version_index(&self, key: &str, index: &FileVersionIndex) -> Result<()> {
        let path = self.version_index_path(key);
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
            return Ok(());
        };

        let manifest_hash = index
            .versions
            .get(preferred_head)
            .map(|record| record.manifest_hash.clone())
            .with_context(|| {
                format!("preferred head {preferred_head} missing in index for key={key}")
            })?;

        self.current_state
            .objects
            .insert(key.to_string(), manifest_hash);
        Ok(())
    }

    async fn persist_current_state(&self) -> Result<()> {
        let payload = serde_json::to_vec_pretty(&self.current_state)?;
        write_atomic(&self.current_state_path, &payload).await
    }

    async fn create_snapshot(&self) -> Result<String> {
        let created_at_unix = unix_ts();
        let object_map_payload = serde_json::to_vec(&self.current_state.objects)?;
        let state_hash = hash_hex(&object_map_payload);
        let snapshot_id = format!("snap-{}-{}", unix_ts_nanos(), &state_hash[..12]);

        let manifest = SnapshotManifest {
            id: snapshot_id.clone(),
            created_at_unix,
            objects: self.current_state.objects.clone(),
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

    fn version_index_path(&self, key: &str) -> PathBuf {
        let key_hash = hash_hex(key.as_bytes());
        self.versions_dir.join(format!("{key_hash}.json"))
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
}

fn empty_version_index(key: &str) -> FileVersionIndex {
    FileVersionIndex {
        key: key.to_string(),
        versions: HashMap::new(),
        head_version_ids: Vec::new(),
        preferred_head_version_id: None,
    }
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
