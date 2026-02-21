use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
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
pub struct PutResult {
    pub snapshot_id: String,
    pub new_chunks: usize,
    pub dedup_reused_chunks: usize,
}

pub struct PersistentStore {
    root_dir: PathBuf,
    chunks_dir: PathBuf,
    manifests_dir: PathBuf,
    snapshots_dir: PathBuf,
    current_state_path: PathBuf,
    current_state: CurrentState,
}

impl PersistentStore {
    pub async fn init(root_dir: impl Into<PathBuf>) -> Result<Self> {
        let root_dir = root_dir.into();
        let chunks_dir = root_dir.join("chunks");
        let manifests_dir = root_dir.join("manifests");
        let snapshots_dir = root_dir.join("snapshots");
        let state_dir = root_dir.join("state");
        let current_state_path = state_dir.join("current.json");

        fs::create_dir_all(&chunks_dir).await?;
        fs::create_dir_all(&manifests_dir).await?;
        fs::create_dir_all(&snapshots_dir).await?;
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

    pub async fn put_object(&mut self, key: &str, payload: Bytes) -> Result<PutResult> {
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
        let manifest_path = self
            .manifests_dir
            .join(format!("{manifest_hash}.json"));

        if !fs::try_exists(&manifest_path).await? {
            write_atomic(&manifest_path, &manifest_bytes).await?;
        }

        self.current_state
            .objects
            .insert(key.to_string(), manifest_hash.clone());
        self.persist_current_state().await?;

        let snapshot_id = self.create_snapshot().await?;

        Ok(PutResult {
            snapshot_id,
            new_chunks,
            dedup_reused_chunks,
        })
    }

    pub async fn get_object(
        &self,
        key: &str,
        snapshot_id: Option<&str>,
    ) -> std::result::Result<Bytes, StoreReadError> {
        let manifest_hash = match snapshot_id {
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
        .ok_or(StoreReadError::NotFound)?;

        let manifest_path = self
            .manifests_dir
            .join(format!("{manifest_hash}.json"));

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
