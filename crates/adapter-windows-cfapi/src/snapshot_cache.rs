#![cfg(windows)]

use crate::auth::is_internal_client_identity_relative_path;
use crate::cfapi::{cf_get_placeholder_standard_info, open_sync_path, path_is_placeholder};
use crate::connection_config::is_internal_connection_bootstrap_relative_path;
use crate::helpers::normalize_path;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use sync_core::{EntryKind, SyncSnapshot};

const DEFAULT_REMOTE_SNAPSHOT_CACHE_FILE_NAME: &str = ".ironmesh-remote-snapshot.json";
const SYNTHETIC_SERVER_HEAD_HASH_PREFIX: &str = "server-head:";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RemoteDeleteReconcileReport {
    pub deleted_paths: BTreeSet<String>,
    pub preserved_paths: BTreeSet<String>,
    pub suppressed_startup_paths: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSnapshotCache {
    pub captured_at_unix_ms: u64,
    pub snapshot: SyncSnapshot,
    #[serde(default)]
    pub local_file_hashes_by_path: BTreeMap<String, LocalFileHashBaseline>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalFileHashBaseline {
    pub content_hash: String,
    #[serde(default)]
    pub recorded_at_unix_ms: u64,
}

impl RemoteSnapshotCache {
    pub fn from_snapshot(snapshot: SyncSnapshot) -> Self {
        Self {
            captured_at_unix_ms: current_unix_ms(),
            snapshot,
            local_file_hashes_by_path: BTreeMap::new(),
        }
    }

    pub fn with_snapshot(&self, snapshot: SyncSnapshot) -> Self {
        Self {
            captured_at_unix_ms: current_unix_ms(),
            local_file_hashes_by_path: filter_local_file_hashes_for_snapshot(
                &snapshot,
                self.local_file_hashes_by_path.clone(),
            ),
            snapshot,
        }
    }
}

pub fn default_remote_snapshot_cache_path(sync_root_path: &Path) -> PathBuf {
    sync_root_path.join(DEFAULT_REMOTE_SNAPSHOT_CACHE_FILE_NAME)
}

pub fn is_internal_remote_snapshot_relative_path(path: &str) -> bool {
    let normalized = path.trim().trim_matches(['/', '\\']).replace('\\', "/");
    normalized == DEFAULT_REMOTE_SNAPSHOT_CACHE_FILE_NAME
        || normalized.ends_with(&format!("/{DEFAULT_REMOTE_SNAPSHOT_CACHE_FILE_NAME}"))
}

pub fn load_remote_snapshot_cache(sync_root_path: &Path) -> Result<Option<RemoteSnapshotCache>> {
    with_locked_cache(|| load_remote_snapshot_cache_unlocked(sync_root_path))
}

pub fn persist_remote_snapshot_cache(
    sync_root_path: &Path,
    snapshot: &SyncSnapshot,
) -> Result<RemoteSnapshotCache> {
    with_locked_cache(|| {
        let cache = load_remote_snapshot_cache_unlocked(sync_root_path)?
            .map(|existing| existing.with_snapshot(snapshot.clone()))
            .unwrap_or_else(|| RemoteSnapshotCache::from_snapshot(snapshot.clone()));
        write_remote_snapshot_cache_unlocked(sync_root_path, &cache)?;
        Ok(cache)
    })
}

pub fn record_local_file_hash(sync_root_path: &Path, relative_path: &str) -> Result<()> {
    let normalized = normalize_path(relative_path);
    if normalized.is_empty() || is_internal_sync_root_relative_path(&normalized) {
        return Ok(());
    }

    let full_path = sync_root_path.join(normalized.replace('/', "\\"));
    let metadata = fs::metadata(&full_path)
        .with_context(|| format!("failed to inspect {}", full_path.display()))?;
    if metadata.is_dir() {
        return Ok(());
    }

    let content_hash = hash_file(&full_path)?;
    let recorded_at_unix_ms = current_unix_ms();
    with_locked_cache(|| {
        let mut cache = load_remote_snapshot_cache_unlocked(sync_root_path)?
            .unwrap_or_else(|| RemoteSnapshotCache::from_snapshot(SyncSnapshot::default()));
        cache.local_file_hashes_by_path.insert(
            normalized,
            LocalFileHashBaseline {
                content_hash,
                recorded_at_unix_ms,
            },
        );
        write_remote_snapshot_cache_unlocked(sync_root_path, &cache)?;
        Ok(())
    })
}

pub fn reconcile_remote_delete_state(
    sync_root_path: &Path,
    previous_cache: Option<&RemoteSnapshotCache>,
    current_snapshot: &SyncSnapshot,
) -> Result<RemoteDeleteReconcileReport> {
    let Some(previous_cache) = previous_cache else {
        return Ok(RemoteDeleteReconcileReport::default());
    };
    let previous_snapshot = &previous_cache.snapshot;

    let previous_remote_files = remote_file_index(previous_snapshot);
    if previous_remote_files.is_empty() {
        return Ok(RemoteDeleteReconcileReport::default());
    }

    let current_remote_files = current_remote_file_paths(current_snapshot);
    let mut report = RemoteDeleteReconcileReport::default();
    let mut deleted_candidates = previous_remote_files
        .iter()
        .filter(|(path, _)| !current_remote_files.contains(path.as_str()))
        .map(|(path, remote_hash)| (path.clone(), remote_hash.clone()))
        .collect::<Vec<_>>();
    deleted_candidates.sort_by(|(left, _), (right, _)| {
        right
            .matches('/')
            .count()
            .cmp(&left.matches('/').count())
            .then_with(|| right.cmp(left))
    });

    for (path, previous_remote_hash) in deleted_candidates {
        if is_internal_sync_root_relative_path(&path) {
            continue;
        }

        let full_path = sync_root_path.join(path.replace('/', "\\"));
        let metadata = match fs::metadata(&full_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                tracing::info!(
                    "remote-delete-reconcile: failed to inspect {}: {}",
                    full_path.display(),
                    error
                );
                continue;
            }
        };
        if metadata.is_dir() {
            continue;
        }

        let previous_local_hash = previous_cache
            .local_file_hashes_by_path
            .get(&path)
            .map(|baseline| baseline.content_hash.as_str());
        let unchanged_local = local_path_matches_previous_remote_state(
            &full_path,
            previous_local_hash,
            previous_remote_hash.as_deref(),
            previous_cache.captured_at_unix_ms,
        )?;
        if !unchanged_local {
            report.preserved_paths.insert(path);
            continue;
        }

        match fs::remove_file(&full_path) {
            Ok(()) => {
                report.deleted_paths.insert(path.clone());
                tracing::info!(
                    "remote-delete-reconcile: removed stale local file {} after remote delete",
                    full_path.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::info!(
                    "remote-delete-reconcile: failed to remove stale local file {}: {}",
                    full_path.display(),
                    error
                );
                report.suppressed_startup_paths.insert(path);
            }
        }
    }

    Ok(report)
}

fn remote_file_index(snapshot: &SyncSnapshot) -> BTreeMap<String, Option<String>> {
    let mut index = BTreeMap::new();
    for entry in &snapshot.remote {
        if entry.kind != EntryKind::File {
            continue;
        }
        index.insert(
            normalize_path(&entry.path),
            entry.content_hash.as_ref().map(|value| value.to_string()),
        );
    }
    index
}

fn current_remote_file_paths(snapshot: &SyncSnapshot) -> BTreeSet<String> {
    snapshot
        .remote
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
        .map(|entry| normalize_path(&entry.path))
        .collect()
}

fn local_path_matches_previous_remote_state(
    full_path: &Path,
    previous_local_hash: Option<&str>,
    previous_remote_hash: Option<&str>,
    previous_captured_at_unix_ms: u64,
) -> Result<bool> {
    if path_is_placeholder(full_path)
        && let Ok(file) = open_sync_path(full_path, false)
        && let Ok(info) = cf_get_placeholder_standard_info(&file)
    {
        return Ok(info.ModifiedDataSize == 0);
    }

    if let Some(previous_local_hash) = previous_local_hash.filter(|value| !value.trim().is_empty())
        && hash_file(full_path)? == previous_local_hash
    {
        return Ok(true);
    }

    if let Some(previous_remote_hash) = previous_remote_hash
        .filter(|value| !value.trim().is_empty())
        .filter(|value| !value.starts_with(SYNTHETIC_SERVER_HEAD_HASH_PREFIX))
        && hash_file(full_path)? == previous_remote_hash
    {
        return Ok(true);
    }

    if previous_captured_at_unix_ms == 0 {
        return Ok(false);
    }

    let metadata = match fs::metadata(full_path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(false),
    };
    if metadata.len() > 0 {
        return Ok(false);
    }

    let modified_unix_ms = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    if modified_unix_ms == 0 {
        return Ok(false);
    }

    Ok(modified_unix_ms <= previous_captured_at_unix_ms.saturating_add(2_000))
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

fn is_internal_sync_root_relative_path(path: &str) -> bool {
    is_internal_client_identity_relative_path(path)
        || is_internal_connection_bootstrap_relative_path(path)
        || is_internal_remote_snapshot_relative_path(path)
}

fn filter_local_file_hashes_for_snapshot(
    snapshot: &SyncSnapshot,
    local_file_hashes_by_path: BTreeMap<String, LocalFileHashBaseline>,
) -> BTreeMap<String, LocalFileHashBaseline> {
    let remote_paths = current_remote_file_paths(snapshot);
    local_file_hashes_by_path
        .into_iter()
        .filter(|(path, _)| remote_paths.contains(path.as_str()))
        .collect()
}

fn load_remote_snapshot_cache_unlocked(sync_root_path: &Path) -> Result<Option<RemoteSnapshotCache>> {
    let cache_path = default_remote_snapshot_cache_path(sync_root_path);
    match fs::read(&cache_path) {
        Ok(payload) => {
            if let Ok(cache) = serde_json::from_slice::<RemoteSnapshotCache>(&payload) {
                return Ok(Some(cache));
            }

            let snapshot = serde_json::from_slice::<SyncSnapshot>(&payload)
                .with_context(|| format!("failed to parse {}", cache_path.display()))?;
            let captured_at_unix_ms = fs::metadata(&cache_path)
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0);
            Ok(Some(RemoteSnapshotCache {
                captured_at_unix_ms,
                snapshot,
                local_file_hashes_by_path: BTreeMap::new(),
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to read remote snapshot cache {}",
                cache_path.display()
            )
        }),
    }
}

fn write_remote_snapshot_cache_unlocked(
    sync_root_path: &Path,
    cache: &RemoteSnapshotCache,
) -> Result<()> {
    let cache_path = default_remote_snapshot_cache_path(sync_root_path);
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let payload = serde_json::to_vec_pretty(cache)
        .with_context(|| format!("failed to encode {}", cache_path.display()))?;
    let temp_path = cache_path.with_extension("tmp");
    fs::write(&temp_path, payload)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    fs::rename(&temp_path, &cache_path).with_context(|| {
        format!(
            "failed to place remote snapshot cache {} into {}",
            temp_path.display(),
            cache_path.display()
        )
    })?;
    Ok(())
}

fn with_locked_cache<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    static REMOTE_SNAPSHOT_CACHE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = REMOTE_SNAPSHOT_CACHE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("remote snapshot cache lock poisoned");
    f()
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync_core::NamespaceEntry;

    #[test]
    fn internal_remote_snapshot_path_detection_matches_nested_and_root_relative_paths() {
        assert!(is_internal_remote_snapshot_relative_path(
            ".ironmesh-remote-snapshot.json"
        ));
        assert!(is_internal_remote_snapshot_relative_path(
            "nested/.ironmesh-remote-snapshot.json"
        ));
        assert!(!is_internal_remote_snapshot_relative_path(
            "nested/not-remote-snapshot.json"
        ));
    }

    #[test]
    fn persist_and_load_remote_snapshot_cache_round_trip() {
        let sync_root = std::env::temp_dir().join(format!(
            "ironmesh-remote-snapshot-cache-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&sync_root).expect("sync root should exist");
        let snapshot = SyncSnapshot {
            local: Vec::new(),
            remote: vec![NamespaceEntry::file(
                "docs/readme.txt",
                "v1",
                "hash-1",
            )],
        };

        persist_remote_snapshot_cache(&sync_root, &snapshot)
            .expect("snapshot cache should persist");
        let loaded = load_remote_snapshot_cache(&sync_root)
            .expect("snapshot cache should reload")
            .expect("snapshot cache should exist");

        assert_eq!(loaded.snapshot, snapshot);
        assert!(loaded.captured_at_unix_ms > 0);
        assert!(loaded.local_file_hashes_by_path.is_empty());

        let _ = fs::remove_dir_all(sync_root);
    }
}
