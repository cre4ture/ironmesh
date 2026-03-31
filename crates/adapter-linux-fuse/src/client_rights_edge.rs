#![cfg(not(windows))]

use crate::runtime::ReplayAction;
use anyhow::{Context, Result, anyhow};
use client_sdk::IronMeshClient;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sync_core::{EntryKind, HydrationState, LocalEntry, NamespaceEntry, PinState, SyncSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineObjectCacheMode {
    On,
    Off,
}

impl OfflineObjectCacheMode {
    pub fn enabled(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Debug)]
pub struct ClientRightsEdgeState {
    queue_path: PathBuf,
    snapshot_path: PathBuf,
    staged_dir: PathBuf,
    upload_state_dir: PathBuf,
    object_cache_dir: PathBuf,
    queue: Mutex<MutationLog>,
    object_cache_mode: OfflineObjectCacheMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MutationLog {
    next_id: u64,
    pending: Vec<PendingMutation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingMutation {
    id: u64,
    created_at_unix_ms: u64,
    op: PendingMutationOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PendingMutationOp {
    UploadFile {
        path: String,
        staged_rel_path: String,
        upload_state_rel_path: String,
        size: u64,
        base_remote_version: Option<String>,
        content_hash: String,
    },
    EnsureDirectory {
        path: String,
    },
    DeletePath {
        path: String,
        directory: bool,
        base_remote_version: Option<String>,
    },
    RenamePath {
        from_path: String,
        to_path: String,
        overwrite: bool,
        base_remote_version: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct OverlayFileEntry {
    path: String,
    size: u64,
    content_hash: String,
    base_remote_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyMutationResult {
    Applied,
    Conflict,
}

impl ClientRightsEdgeState {
    pub fn new(
        root_dir: impl Into<PathBuf>,
        object_cache_mode: OfflineObjectCacheMode,
    ) -> Result<Self> {
        let root_dir = root_dir.into();
        let queue_path = root_dir.join("state").join("pending-mutations.json");
        let snapshot_path = root_dir.join("state").join("remote-snapshot.json");
        let staged_dir = root_dir.join("staged");
        let upload_state_dir = root_dir.join("upload-state");
        let object_cache_dir = root_dir.join("object-cache");

        fs::create_dir_all(queue_path.parent().unwrap_or(&root_dir))
            .with_context(|| format!("failed to create {}", root_dir.display()))?;
        fs::create_dir_all(&staged_dir)
            .with_context(|| format!("failed to create {}", staged_dir.display()))?;
        fs::create_dir_all(&upload_state_dir)
            .with_context(|| format!("failed to create {}", upload_state_dir.display()))?;
        fs::create_dir_all(&object_cache_dir)
            .with_context(|| format!("failed to create {}", object_cache_dir.display()))?;

        let mut queue = load_json_file::<MutationLog>(&queue_path)?.unwrap_or_default();
        if queue.next_id == 0 {
            queue.next_id = queue.pending.iter().map(|entry| entry.id).max().unwrap_or(0) + 1;
        }

        Ok(Self {
            queue_path,
            snapshot_path,
            staged_dir,
            upload_state_dir,
            object_cache_dir,
            queue: Mutex::new(queue),
            object_cache_mode,
        })
    }

    pub fn load_cached_snapshot(&self) -> Result<Option<SyncSnapshot>> {
        load_json_file(&self.snapshot_path)
    }

    pub fn persist_snapshot(&self, snapshot: &SyncSnapshot) -> Result<()> {
        persist_json_file_atomic(&self.snapshot_path, snapshot)
    }

    pub fn enqueue_upload(
        &self,
        path: &str,
        base_remote_version: Option<&str>,
        reader: &mut dyn Read,
        length: u64,
    ) -> Result<()> {
        if path.ends_with('/') {
            return self.enqueue_directory(path);
        }

        let path = normalize_logical_path(path);
        let mut queue = self.queue.lock().map_err(|_| anyhow!("queue lock poisoned"))?;
        let id = next_queue_id(&mut queue);
        let staged_rel_path = format!("{id}.bin");
        let upload_state_rel_path = format!("{id}.json");
        let staged_path = self.staged_dir.join(&staged_rel_path);
        let content_hash = stage_reader_to_file(reader, length, &staged_path)?;
        queue.pending.push(PendingMutation {
            id,
            created_at_unix_ms: unix_ms(),
            op: PendingMutationOp::UploadFile {
                path,
                staged_rel_path,
                upload_state_rel_path,
                size: length,
                base_remote_version: base_remote_version.map(ToString::to_string),
                content_hash,
            },
        });
        persist_json_file_atomic(&self.queue_path, &*queue)
    }

    pub fn enqueue_directory(&self, path: &str) -> Result<()> {
        let path = normalize_logical_path(path.trim_end_matches('/'));
        let mut queue = self.queue.lock().map_err(|_| anyhow!("queue lock poisoned"))?;
        let id = next_queue_id(&mut queue);
        queue.pending.push(PendingMutation {
            id,
            created_at_unix_ms: unix_ms(),
            op: PendingMutationOp::EnsureDirectory { path },
        });
        persist_json_file_atomic(&self.queue_path, &*queue)
    }

    pub fn enqueue_delete(
        &self,
        path: &str,
        base_remote_version: Option<&str>,
        directory: bool,
    ) -> Result<()> {
        let path = normalize_logical_path(path.trim_end_matches('/'));
        let mut queue = self.queue.lock().map_err(|_| anyhow!("queue lock poisoned"))?;
        let id = next_queue_id(&mut queue);
        queue.pending.push(PendingMutation {
            id,
            created_at_unix_ms: unix_ms(),
            op: PendingMutationOp::DeletePath {
                path,
                directory,
                base_remote_version: base_remote_version.map(ToString::to_string),
            },
        });
        persist_json_file_atomic(&self.queue_path, &*queue)
    }

    pub fn enqueue_rename(
        &self,
        from_path: &str,
        to_path: &str,
        overwrite: bool,
        base_remote_version: Option<&str>,
    ) -> Result<()> {
        let mut queue = self.queue.lock().map_err(|_| anyhow!("queue lock poisoned"))?;
        let id = next_queue_id(&mut queue);
        queue.pending.push(PendingMutation {
            id,
            created_at_unix_ms: unix_ms(),
            op: PendingMutationOp::RenamePath {
                from_path: normalize_logical_path(from_path),
                to_path: normalize_logical_path(to_path),
                overwrite,
                base_remote_version: base_remote_version.map(ToString::to_string),
            },
        });
        persist_json_file_atomic(&self.queue_path, &*queue)
    }

    pub fn replay_actions(&self) -> Result<Vec<ReplayAction>> {
        let queue = self.queue.lock().map_err(|_| anyhow!("queue lock poisoned"))?;
        let mut actions = Vec::with_capacity(queue.pending.len());
        for mutation in &queue.pending {
            match &mutation.op {
                PendingMutationOp::UploadFile {
                    path,
                    staged_rel_path,
                    ..
                } => {
                    let staged_path = self.staged_dir.join(staged_rel_path);
                    let data = fs::read(&staged_path).with_context(|| {
                        format!("failed to read staged mutation {}", staged_path.display())
                    })?;
                    actions.push(ReplayAction::UpsertFile {
                        path: path.clone(),
                        data,
                    });
                }
                PendingMutationOp::EnsureDirectory { path } => {
                    actions.push(ReplayAction::EnsureDirectory { path: path.clone() });
                }
                PendingMutationOp::DeletePath {
                    path, directory, ..
                } => {
                    actions.push(ReplayAction::DeletePath {
                        path: path.clone(),
                        directory: *directory,
                    });
                }
                PendingMutationOp::RenamePath {
                    from_path,
                    to_path,
                    overwrite,
                    ..
                } => {
                    actions.push(ReplayAction::RenamePath {
                        from_path: from_path.clone(),
                        to_path: to_path.clone(),
                        overwrite: *overwrite,
                    });
                }
            }
        }
        Ok(actions)
    }

    pub fn planning_snapshot(&self, remote_snapshot: &SyncSnapshot) -> Result<SyncSnapshot> {
        let overlay_files = self.overlay_files()?;
        let remote_versions = remote_snapshot
            .remote
            .iter()
            .filter_map(|entry| {
                (entry.kind == EntryKind::File)
                    .then_some((entry.path.as_str(), entry.version.as_deref()))
            })
            .collect::<BTreeMap<_, _>>();

        let mut local = Vec::with_capacity(overlay_files.len());
        for entry in overlay_files.values() {
            let remote_version = remote_versions
                .get(entry.path.as_str())
                .copied()
                .flatten()
                .map(ToString::to_string);
            let conflict = remote_version_forces_conflict(
                entry.base_remote_version.as_deref(),
                remote_version.as_deref(),
            );
            let local_version = conflict.then(|| {
                let short_hash = &entry.content_hash[..entry.content_hash.len().min(12)];
                format!("local-pending:{short_hash}")
            });
            local.push(LocalEntry::new(
                NamespaceEntry {
                    path: entry.path.clone(),
                    kind: EntryKind::File,
                    version: local_version,
                    content_hash: Some(entry.content_hash.clone()),
                    size_bytes: Some(entry.size),
                },
                PinState::Pinned,
                HydrationState::Hydrated,
            ));
        }

        Ok(SyncSnapshot {
            local,
            remote: remote_snapshot.remote.clone(),
        })
    }

    pub fn read_cached_object(&self, path: &str, version: &str) -> Result<Option<Vec<u8>>> {
        if !self.object_cache_mode.enabled() {
            return Ok(None);
        }

        let cache_path = self.object_cache_path(path, version);
        match fs::read(&cache_path) {
            Ok(payload) => Ok(Some(payload)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error)
                .with_context(|| format!("failed to read {}", cache_path.display())),
        }
    }

    pub fn cache_full_object(&self, path: &str, version: &str, payload: &[u8]) -> Result<()> {
        if !self.object_cache_mode.enabled() {
            return Ok(());
        }
        let cache_path = self.object_cache_path(path, version);
        write_atomic(&cache_path, payload)
    }

    pub fn spawn_sync_loop(
        self: &Arc<Self>,
        running: Arc<AtomicBool>,
        client: IronMeshClient,
        retry_interval: Duration,
    ) -> JoinHandle<()> {
        let state = Arc::clone(self);
        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let next = match state.peek_next_mutation() {
                    Ok(Some(next)) => next,
                    Ok(None) => {
                        sleep_until_or_stop(retry_interval, &running);
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!("client-rights-edge: failed reading queue: {error}");
                        sleep_until_or_stop(retry_interval, &running);
                        continue;
                    }
                };

                match state.apply_mutation(&client, &next) {
                    Ok(ApplyMutationResult::Applied) => {
                        if let Err(error) = state.complete_mutation(next.id) {
                            tracing::warn!(
                                "client-rights-edge: failed to finalize mutation {}: {error}",
                                next.id
                            );
                            sleep_until_or_stop(retry_interval, &running);
                        }
                    }
                    Ok(ApplyMutationResult::Conflict) => {
                        tracing::warn!(
                            "client-rights-edge: pending mutation {} blocked by remote divergence",
                            next.id
                        );
                        sleep_until_or_stop(retry_interval, &running);
                    }
                    Err(error) => {
                        tracing::warn!(
                            "client-rights-edge: mutation {} sync attempt failed: {error}",
                            next.id
                        );
                        sleep_until_or_stop(retry_interval, &running);
                    }
                }
            }
        })
    }

    fn peek_next_mutation(&self) -> Result<Option<PendingMutation>> {
        let queue = self.queue.lock().map_err(|_| anyhow!("queue lock poisoned"))?;
        Ok(queue.pending.first().cloned())
    }

    fn complete_mutation(&self, id: u64) -> Result<()> {
        let removed = {
            let mut queue = self.queue.lock().map_err(|_| anyhow!("queue lock poisoned"))?;
            let Some(index) = queue.pending.iter().position(|entry| entry.id == id) else {
                return Ok(());
            };
            let removed = queue.pending.remove(index);
            persist_json_file_atomic(&self.queue_path, &*queue)?;
            removed
        };

        if let PendingMutationOp::UploadFile {
            staged_rel_path,
            upload_state_rel_path,
            ..
        } = removed.op
        {
            remove_file_if_exists(&self.staged_dir.join(staged_rel_path))?;
            remove_file_if_exists(&self.upload_state_dir.join(upload_state_rel_path))?;
        }

        Ok(())
    }

    fn apply_mutation(&self, client: &IronMeshClient, mutation: &PendingMutation) -> Result<ApplyMutationResult> {
        match &mutation.op {
            PendingMutationOp::UploadFile {
                path,
                staged_rel_path,
                upload_state_rel_path,
                base_remote_version,
                ..
            } => {
                if self.cached_snapshot_reports_conflict(path, base_remote_version.as_deref())? {
                    return Ok(ApplyMutationResult::Conflict);
                }

                let staged_path = self.staged_dir.join(staged_rel_path);
                let upload_state_path = self.upload_state_dir.join(upload_state_rel_path);
                client
                    .put_file_resumable(path, &staged_path, &upload_state_path)
                    .with_context(|| format!("failed to upload staged file {}", staged_path.display()))?;
                Ok(ApplyMutationResult::Applied)
            }
            PendingMutationOp::EnsureDirectory { path } => {
                let marker = format!("{}/", path.trim_end_matches('/'));
                let mut reader = Cursor::new(Vec::new());
                client
                    .put_large_aware_reader(marker, &mut reader, 0)
                    .with_context(|| format!("failed to create remote directory marker for {path}"))?;
                Ok(ApplyMutationResult::Applied)
            }
            PendingMutationOp::DeletePath {
                path, directory, ..
            } => {
                let key = if *directory {
                    format!("{}/", path.trim_end_matches('/'))
                } else {
                    path.clone()
                };
                client
                    .delete_path_blocking(&key)
                    .with_context(|| format!("failed to delete remote path {key}"))?;
                Ok(ApplyMutationResult::Applied)
            }
            PendingMutationOp::RenamePath {
                from_path,
                to_path,
                overwrite,
                base_remote_version,
            } => {
                if base_remote_version.is_some()
                    && self.cached_snapshot_reports_conflict(
                        from_path,
                        base_remote_version.as_deref(),
                    )?
                {
                    return Ok(ApplyMutationResult::Conflict);
                }
                client
                    .rename_path_blocking(from_path.clone(), to_path.clone(), *overwrite)
                    .with_context(|| format!("failed to rename remote path {from_path} -> {to_path}"))?;
                Ok(ApplyMutationResult::Applied)
            }
        }
    }

    fn cached_snapshot_reports_conflict(
        &self,
        path: &str,
        base_remote_version: Option<&str>,
    ) -> Result<bool> {
        let current_version = self
            .load_cached_snapshot()?
            .and_then(|snapshot| remote_file_version(&snapshot, path));
        Ok(remote_version_forces_conflict(
            base_remote_version,
            current_version.as_deref(),
        ))
    }

    fn overlay_files(&self) -> Result<BTreeMap<String, OverlayFileEntry>> {
        let queue = self.queue.lock().map_err(|_| anyhow!("queue lock poisoned"))?;
        let mut overlay_files = BTreeMap::new();
        for mutation in &queue.pending {
            match &mutation.op {
                PendingMutationOp::UploadFile {
                    path,
                    size,
                    content_hash,
                    base_remote_version,
                    ..
                } => {
                    overlay_files.insert(
                        path.clone(),
                        OverlayFileEntry {
                            path: path.clone(),
                            size: *size,
                            content_hash: content_hash.clone(),
                            base_remote_version: base_remote_version.clone(),
                        },
                    );
                }
                PendingMutationOp::RenamePath {
                    from_path, to_path, ..
                } => {
                    let moved = overlay_files
                        .keys()
                        .filter(|path| is_same_or_child(path, from_path))
                        .cloned()
                        .collect::<Vec<_>>();
                    for old_path in moved {
                        if let Some(mut entry) = overlay_files.remove(&old_path) {
                            entry.path = rename_path_prefix(&old_path, from_path, to_path)?;
                            overlay_files.insert(entry.path.clone(), entry);
                        }
                    }
                }
                PendingMutationOp::DeletePath {
                    path, directory, ..
                } => {
                    if *directory {
                        overlay_files.retain(|candidate, _| !is_same_or_child(candidate, path));
                    } else {
                        overlay_files.remove(path);
                    }
                }
                PendingMutationOp::EnsureDirectory { .. } => {}
            }
        }
        Ok(overlay_files)
    }

    fn object_cache_path(&self, path: &str, version: &str) -> PathBuf {
        let cache_key = blake3::hash(format!("{path}\u{0}{version}").as_bytes())
            .to_hex()
            .to_string();
        self.object_cache_dir
            .join(&cache_key[..2])
            .join(format!("{cache_key}.bin"))
    }
}

fn next_queue_id(queue: &mut MutationLog) -> u64 {
    let id = queue.next_id.max(1);
    queue.next_id = id.saturating_add(1);
    id
}

fn stage_reader_to_file(reader: &mut dyn Read, length: u64, path: &Path) -> Result<String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let temp_path = path.with_extension("tmp");
    let mut file =
        File::create(&temp_path).with_context(|| format!("failed to create {}", temp_path.display()))?;
    let mut limited = reader.take(length);
    let mut hasher = blake3::Hasher::new();
    let mut remaining = length;
    let mut buffer = vec![0_u8; 64 * 1024];

    while remaining > 0 {
        let read = limited
            .read(&mut buffer)
            .with_context(|| format!("failed reading staged payload for {}", path.display()))?;
        if read == 0 {
            break;
        }
        file.write_all(&buffer[..read])
            .with_context(|| format!("failed writing staged payload {}", temp_path.display()))?;
        hasher.update(&buffer[..read]);
        remaining = remaining.saturating_sub(read as u64);
    }

    if remaining != 0 {
        return Err(anyhow!(
            "staged payload truncated for {}: missing {} bytes",
            path.display(),
            remaining
        ));
    }

    file.flush()
        .with_context(|| format!("failed to flush {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to place staged payload {} into {}",
            temp_path.display(),
            path.display()
        )
    })?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn normalize_logical_path(path: &str) -> String {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn remote_file_version(snapshot: &SyncSnapshot, path: &str) -> Option<String> {
    snapshot.remote.iter().find_map(|entry| {
        (entry.kind == EntryKind::File && entry.path == path)
            .then(|| entry.version.clone())
            .flatten()
    })
}

fn remote_version_forces_conflict(
    base_remote_version: Option<&str>,
    current_remote_version: Option<&str>,
) -> bool {
    match (base_remote_version, current_remote_version) {
        (None, None) => false,
        (Some(base), Some(current)) if base == current => false,
        _ => true,
    }
}

fn is_same_or_child(candidate: &str, root: &str) -> bool {
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn rename_path_prefix(path: &str, from_root: &str, to_root: &str) -> Result<String> {
    let relative = path
        .strip_prefix(from_root)
        .ok_or_else(|| anyhow!("path {path} not under root {from_root}"))?;
    if relative.is_empty() {
        return Ok(to_root.to_string());
    }
    let relative = relative
        .strip_prefix('/')
        .ok_or_else(|| anyhow!("path {path} escaped rename root {from_root}"))?;
    Ok(format!("{to_root}/{relative}"))
}

fn sleep_until_or_stop(duration: Duration, running: &AtomicBool) {
    if duration.is_zero() {
        return;
    }

    let mut remaining = duration;
    let step = Duration::from_millis(100);
    while remaining > Duration::ZERO && running.load(Ordering::SeqCst) {
        let nap = if remaining > step { step } else { remaining };
        thread::sleep(nap);
        remaining = remaining.saturating_sub(nap);
    }
}

fn load_json_file<T>(path: &Path) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::read(path) {
        Ok(payload) => serde_json::from_slice(&payload)
            .with_context(|| format!("failed to parse {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn persist_json_file_atomic<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let payload = serde_json::to_vec_pretty(value)
        .with_context(|| format!("failed to encode {}", path.display()))?;
    write_atomic(path, &payload)
}

fn write_atomic(path: &Path, payload: &[u8]) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(anyhow!("path has no parent: {}", path.display()));
    };
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let temp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("edge-state")
    ));
    fs::write(&temp_path, payload)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to place temporary state {} into {}",
            temp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ironmesh-client-rights-edge-test-{label}-{}",
            unix_ms()
        ));
        fs::create_dir_all(&path).expect("failed to create temp state dir");
        path
    }

    #[test]
    fn planning_snapshot_only_marks_conflict_when_remote_version_diverged() {
        let state_dir = temp_state_dir("planning");
        let state = ClientRightsEdgeState::new(&state_dir, OfflineObjectCacheMode::On)
            .expect("state should initialize");

        let mut reader = Cursor::new(b"offline-change".to_vec());
        state
            .enqueue_upload("docs/report.txt", Some("v1"), &mut reader, 14)
            .expect("upload should queue");

        let unchanged_remote = SyncSnapshot {
            local: Vec::new(),
            remote: vec![NamespaceEntry::file_sized(
                "docs/report.txt",
                "v1",
                "h-remote-v1",
                Some(12),
            )],
        };
        let unchanged_planning = state
            .planning_snapshot(&unchanged_remote)
            .expect("planning snapshot should build");
        assert_eq!(unchanged_planning.local.len(), 1);
        assert_eq!(unchanged_planning.local[0].namespace.version, None);

        let changed_remote = SyncSnapshot {
            local: Vec::new(),
            remote: vec![NamespaceEntry::file_sized(
                "docs/report.txt",
                "v2",
                "h-remote-v2",
                Some(16),
            )],
        };
        let changed_planning = state
            .planning_snapshot(&changed_remote)
            .expect("planning snapshot should build");
        assert_eq!(changed_planning.local.len(), 1);
        assert!(
            changed_planning.local[0]
                .namespace
                .version
                .as_deref()
                .is_some_and(|version| version.starts_with("local-pending:"))
        );

        let _ = fs::remove_dir_all(&state_dir);
    }

    #[test]
    fn disabled_object_cache_does_not_persist_payloads() {
        let state_dir = temp_state_dir("cache-off");
        let state = ClientRightsEdgeState::new(&state_dir, OfflineObjectCacheMode::Off)
            .expect("state should initialize");

        state
            .cache_full_object("photos/a.jpg", "v1", b"jpeg")
            .expect("cache operation should no-op");
        assert_eq!(
            state
                .read_cached_object("photos/a.jpg", "v1")
                .expect("cache read should succeed"),
            None
        );

        let _ = fs::remove_dir_all(&state_dir);
    }
}
