use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
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
    pub head_version_ids: Vec<String>,
    pub versions: Vec<VersionRecordSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub created_at_unix: u64,
    pub object_count: usize,
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
}

impl Default for PutOptions {
    fn default() -> Self {
        Self {
            parent_version_ids: Vec::new(),
            state: VersionConsistencyState::Confirmed,
        }
    }
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
    current_state_path: PathBuf,
    current_state: CurrentState,
}

impl PersistentStore {
    pub async fn init(root_dir: impl Into<PathBuf>) -> Result<Self> {
        let root_dir = root_dir.into();
        let chunks_dir = root_dir.join("chunks");
        let manifests_dir = root_dir.join("manifests");
        let snapshots_dir = root_dir.join("snapshots");
        let versions_dir = root_dir.join("versions");
        let state_dir = root_dir.join("state");
        let current_state_path = state_dir.join("current.json");

        fs::create_dir_all(&chunks_dir).await?;
        fs::create_dir_all(&manifests_dir).await?;
        fs::create_dir_all(&snapshots_dir).await?;
        fs::create_dir_all(&versions_dir).await?;
        fs::create_dir_all(&state_dir).await?;

        let current_state = if fs::try_exists(&current_state_path).await? {
            let payload = fs::read(&current_state_path).await?;
            serde_json::from_slice::<CurrentState>(&payload)
                .with_context(|| format!("invalid current state: {}", current_state_path.display()))?
        } else {
            CurrentState::default()
        };

        Ok(Self {
            root_dir,
            chunks_dir,
            manifests_dir,
            snapshots_dir,
            versions_dir,
            current_state_path,
            current_state,
        })
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
            index
                .preferred_head_version_id
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        } else {
            options.parent_version_ids.clone()
        };

        for parent in &parent_version_ids {
            if !index.versions.contains_key(parent) {
                bail!("parent version does not exist for key={key}: {parent}");
            }
        }

        let version_id = format!("ver-{}-{}", unix_ts_nanos(), &manifest_hash[..12]);
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

        let snapshot_id = self.create_snapshot().await?;

        Ok(PutResult {
            snapshot_id,
            version_id,
            state: options.state,
            new_chunks,
            dedup_reused_chunks,
        })
    }

    pub async fn confirm_version(&mut self, key: &str, version_id: &str) -> Result<bool> {
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

        Ok(Some(VersionGraphSummary {
            key: index.key,
            preferred_head_version_id: index.preferred_head_version_id,
            head_version_ids: index.head_version_ids,
            versions,
        }))
    }

    pub async fn get_object(
        &self,
        key: &str,
        snapshot_id: Option<&str>,
        version_id: Option<&str>,
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
        } else {
            match snapshot_id {
                Some(snapshot_id) => {
                    let snapshot = self
                        .read_snapshot(snapshot_id)
                        .await
                        .map_err(StoreReadError::Internal)?;

                    match snapshot {
                        Some(snapshot) => snapshot.objects.get(key).cloned(),
                        None => None,
                    }
                }
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

        snapshots.sort_by(|a, b| b.created_at_unix.cmp(&a.created_at_unix));
        Ok(snapshots)
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
            .with_context(|| format!("preferred head {preferred_head} missing in index for key={key}"))?;

        self.current_state.objects.insert(key.to_string(), manifest_hash);
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

    fn version_index_path(&self, key: &str) -> PathBuf {
        let key_hash = hash_hex(key.as_bytes());
        self.versions_dir.join(format!("{key_hash}.json"))
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

fn choose_preferred_head(index: &FileVersionIndex) -> Option<String> {
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

    heads.first().map(|record| record.version_id.clone())
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
mod tests {
    use super::*;

    fn mk_record(
        version_id: &str,
        state: VersionConsistencyState,
        created_at_unix: u64,
    ) -> FileVersionRecord {
        FileVersionRecord {
            version_id: version_id.to_string(),
            key: "k".to_string(),
            manifest_hash: format!("m-{version_id}"),
            parent_version_ids: Vec::new(),
            state,
            created_at_unix,
        }
    }

    #[test]
    fn preferred_head_prioritizes_confirmed_over_newer_provisional() {
        let mut index = empty_version_index("k");
        index
            .versions
            .insert("v-old-confirmed".to_string(), mk_record("v-old-confirmed", VersionConsistencyState::Confirmed, 10));
        index
            .versions
            .insert("v-new-provisional".to_string(), mk_record("v-new-provisional", VersionConsistencyState::Provisional, 100));
        index.head_version_ids = vec!["v-old-confirmed".to_string(), "v-new-provisional".to_string()];

        let preferred = choose_preferred_head(&index);
        assert_eq!(preferred.as_deref(), Some("v-old-confirmed"));
    }

    #[test]
    fn preferred_head_uses_latest_when_same_state() {
        let mut index = empty_version_index("k");
        index
            .versions
            .insert("v1".to_string(), mk_record("v1", VersionConsistencyState::Confirmed, 11));
        index
            .versions
            .insert("v2".to_string(), mk_record("v2", VersionConsistencyState::Confirmed, 22));
        index.head_version_ids = vec!["v1".to_string(), "v2".to_string()];

        let preferred = choose_preferred_head(&index);
        assert_eq!(preferred.as_deref(), Some("v2"));
    }

    #[test]
    fn preferred_head_none_for_empty_heads() {
        let index = empty_version_index("k");
        assert!(choose_preferred_head(&index).is_none());
    }
}
