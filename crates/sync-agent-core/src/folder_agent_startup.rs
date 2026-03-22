use anyhow::{Context, Result};
use client_sdk::IronMeshClient;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sync_core::{EntryKind, SyncSnapshot};

use crate::folder_agent_state::{PathScope, current_unix_ms};
use crate::{
    LocalEntryKind, LocalTreeState, RemoteTreeIndex, absolute_path, normalize_relative_path,
    transfer_path_stem, transfer_state_root,
};

#[derive(Debug, Clone)]
pub struct StartupConflict {
    pub path: String,
    pub reason: String,
    pub details_json: String,
    pub created_unix_ms: u128,
}

pub fn local_paths_to_preserve_on_startup(
    root_dir: &Path,
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    remote_hashes: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut preserve = BTreeSet::new();

    for (path, entry_state) in local_state {
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }

        let Some(previous) = baseline.and_then(|state| state.get(path)) else {
            if let Some(remote_hash) = remote_hashes.get(path) {
                match local_file_content_hash(root_dir, path) {
                    Ok(local_hash) if local_hash == *remote_hash => continue,
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!(
                            "startup-state: failed to hash local file {path}: {error}; preserving local bytes"
                        );
                    }
                }
            }
            preserve.insert(path.clone());
            continue;
        };

        if previous != entry_state {
            if let Some(remote_hash) = remote_hashes.get(path) {
                match local_file_content_hash(root_dir, path) {
                    Ok(local_hash) if local_hash == *remote_hash => continue,
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!(
                            "startup-state: failed to hash local file {path}: {error}; preserving local bytes"
                        );
                    }
                }
            }
            preserve.insert(path.clone());
        }
    }

    preserve
}

pub fn remote_file_hashes_by_local_path(
    snapshot: &SyncSnapshot,
    scope: &PathScope,
) -> BTreeMap<String, String> {
    let mut by_local_path = BTreeMap::new();

    for entry in &snapshot.remote {
        if entry.kind != EntryKind::File {
            continue;
        }
        let Some(content_hash) = entry.content_hash.as_deref() else {
            continue;
        };
        if content_hash.is_empty() {
            continue;
        }

        let remote_path = normalize_relative_path(&entry.path);
        let Some(local_path) = scope.remote_to_local(&remote_path) else {
            continue;
        };
        if local_path.is_empty() {
            continue;
        }
        by_local_path.insert(local_path, content_hash.to_string());
    }

    by_local_path
}

pub fn remote_file_paths_by_local_path(
    snapshot: &SyncSnapshot,
    scope: &PathScope,
) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();

    for entry in &snapshot.remote {
        if entry.kind != EntryKind::File {
            continue;
        }

        let remote_path = normalize_relative_path(&entry.path);
        let Some(local_path) = scope.remote_to_local(&remote_path) else {
            continue;
        };
        if local_path.is_empty() {
            continue;
        }
        paths.insert(local_path);
    }

    paths
}

pub fn startup_remote_delete_wins_paths(
    root_dir: &Path,
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    baseline_hashes: &BTreeMap<String, String>,
    remote_files: &BTreeSet<String>,
    preserve_local_files: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut delete_wins = BTreeSet::new();

    for (path, entry_state) in local_state {
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }
        if remote_files.contains(path) {
            continue;
        }
        let Some(previous) = baseline.and_then(|state| state.get(path)) else {
            continue;
        };

        if previous == entry_state {
            delete_wins.insert(path.clone());
            continue;
        }

        if preserve_local_files.contains(path) {
            let Some(expected_hash) = baseline_hashes.get(path) else {
                continue;
            };
            match local_file_content_hash(root_dir, path) {
                Ok(local_hash) if local_hash == *expected_hash => {
                    delete_wins.insert(path.clone());
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!(
                        "startup-state: failed to hash local file {path} for remote-delete check: {error}; preserving local bytes"
                    );
                }
            }
        }
    }

    delete_wins
}

struct SleepAfterFirstWrite {
    inner: File,
    delay: Duration,
    slept: bool,
}

impl SleepAfterFirstWrite {
    fn new(inner: File, delay: Duration) -> Self {
        Self {
            inner,
            delay,
            slept: false,
        }
    }

    fn sync_all(&self) -> std::io::Result<()> {
        self.inner.sync_all()
    }
}

impl Write for SleepAfterFirstWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        if !self.slept && written > 0 {
            self.slept = true;
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub fn materialize_remote_conflict_copies(
    root_dir: &Path,
    client: &IronMeshClient,
    scope: &PathScope,
    conflicts: &[StartupConflict],
) -> Result<()> {
    let timestamp = current_unix_ms();
    let staged_download_root = transfer_state_root(root_dir).join("conflict-copies");

    for conflict in conflicts {
        if conflict.reason != "dual_modify_conflict"
            && conflict.reason != "dual_modify_missing_baseline"
        {
            continue;
        }

        let Some(remote_key) = scope.local_to_remote(&conflict.path) else {
            continue;
        };

        let base_relative = format!(".ironmesh-conflicts/remote/{}", conflict.path);
        let base_target = absolute_path(root_dir, &base_relative);
        let file_name = base_target
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "object".to_string());
        let conflict_target =
            base_target.with_file_name(format!("{file_name}.remote-conflict-{timestamp}"));

        let Some(parent) = conflict_target.parent() else {
            continue;
        };

        if let Err(error) = fs::create_dir_all(parent)
            .with_context(|| format!("failed to create conflict directory {}", parent.display()))
        {
            eprintln!("startup-state: {error}");
            continue;
        }

        let temp_name = format!(
            ".{}.ironmesh-part-{}",
            conflict_target
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| "object".to_string()),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let temp_path = conflict_target.with_file_name(temp_name);

        let file = match File::create(&temp_path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!(
                    "startup-state: failed to create conflict temp file {}: {error}",
                    temp_path.display()
                );
                continue;
            }
        };

        if cfg!(debug_assertions) {
            if let Ok(raw) = std::env::var("IRONMESH_TEST_CONFLICT_COPY_SLEEP_AFTER_TEMP_CREATE_MS")
                && let Ok(delay_ms) = raw.parse::<u64>()
                && delay_ms > 0
            {
                thread::sleep(Duration::from_millis(delay_ms));
            }

            if std::env::var("IRONMESH_TEST_CRASH_AFTER_CONFLICT_COPY_TEMP_CREATE")
                .ok()
                .is_some_and(|value| value == "1")
            {
                std::process::abort();
            }
        }

        let delay = if cfg!(debug_assertions) {
            std::env::var("IRONMESH_TEST_CONFLICT_COPY_WRITE_DELAY_MS")
                .ok()
                .and_then(|raw| raw.parse::<u64>().ok())
                .filter(|ms| *ms > 0)
                .map(Duration::from_millis)
                .unwrap_or(Duration::from_millis(0))
        } else {
            Duration::from_millis(0)
        };
        let mut writer = SleepAfterFirstWrite::new(file, delay);
        let staged_stem = transfer_path_stem(&remote_key);
        let staged_target = staged_download_root.join(format!("{staged_stem}.bin"));
        let staged_temp = staged_download_root.join(format!("{staged_stem}.part"));
        let staged_state = staged_download_root.join(format!("{staged_stem}.json"));

        if let Err(error) = client.download_file_resumable(
            &remote_key,
            None,
            None,
            &staged_target,
            &staged_temp,
            &staged_state,
        ) {
            eprintln!(
                "startup-state: failed to download remote conflict copy for {}: {error}",
                conflict.path
            );
            let _ = fs::remove_file(&temp_path);
            continue;
        }

        let copy_result = (|| -> Result<()> {
            let mut staged_file = File::open(&staged_target).with_context(|| {
                format!(
                    "failed to open staged conflict copy download {}",
                    staged_target.display()
                )
            })?;
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let read = staged_file.read(&mut buffer).with_context(|| {
                    format!(
                        "failed to read staged conflict copy download {}",
                        staged_target.display()
                    )
                })?;
                if read == 0 {
                    break;
                }
                writer.write_all(&buffer[..read]).with_context(|| {
                    format!(
                        "failed to write conflict temp file {} from staged download",
                        temp_path.display()
                    )
                })?;
            }
            writer.flush().with_context(|| {
                format!("failed to flush conflict temp file {}", temp_path.display())
            })?;
            Ok(())
        })();

        if let Err(error) = copy_result {
            eprintln!(
                "startup-state: failed to materialize staged remote conflict copy for {}: {error}",
                conflict.path
            );
            let _ = fs::remove_file(&temp_path);
            continue;
        }

        if let Err(error) = writer.sync_all() {
            eprintln!(
                "startup-state: failed to flush conflict temp file {}: {error}",
                temp_path.display()
            );
            let _ = fs::remove_file(&temp_path);
            continue;
        }

        if let Err(error) = fs::rename(&temp_path, &conflict_target) {
            eprintln!(
                "startup-state: failed to write conflict copy {}: {error}",
                conflict_target.display()
            );
            let _ = fs::remove_file(&temp_path);
            continue;
        }

        let _ = fs::remove_file(&staged_target);
        let _ = fs::remove_file(&staged_temp);
        let _ = fs::remove_file(&staged_state);
    }

    Ok(())
}

pub fn startup_add_delete_conflicts(
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    remote_files: &BTreeSet<String>,
    preserve_local_files: &BTreeSet<String>,
    remote_delete_wins_paths: &BTreeSet<String>,
) -> Vec<StartupConflict> {
    let mut conflicts = Vec::new();

    for path in preserve_local_files {
        if remote_files.contains(path) || remote_delete_wins_paths.contains(path) {
            continue;
        }
        let Some(entry_state) = local_state.get(path) else {
            continue;
        };
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }

        let (reason, details_json) = match baseline.and_then(|state| state.get(path)) {
            Some(previous) if previous != entry_state => (
                "modify_delete_conflict",
                json!({
                    "policy": "keep_local_bytes",
                    "local_action": "upload_local",
                    "remote_action": "delete_seen",
                })
                .to_string(),
            ),
            None => (
                "add_delete_ambiguous_missing_baseline",
                json!({
                    "policy": "keep_local_bytes",
                    "local_action": "upload_local",
                    "remote_action": "missing",
                })
                .to_string(),
            ),
            _ => continue,
        };
        conflicts.push(StartupConflict {
            path: path.clone(),
            reason: reason.to_string(),
            details_json,
            created_unix_ms: current_unix_ms(),
        });
    }

    conflicts
}

pub fn startup_dual_modify_conflicts(
    root_dir: &Path,
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    baseline_hashes: &BTreeMap<String, String>,
    remote_hashes: &BTreeMap<String, String>,
    preserve_local_files: &BTreeSet<String>,
) -> Vec<StartupConflict> {
    let mut conflicts = Vec::new();

    for path in preserve_local_files {
        let Some(entry_state) = local_state.get(path) else {
            continue;
        };
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }

        let Some(remote_hash) = remote_hashes.get(path) else {
            continue;
        };

        let local_hash = match local_file_content_hash(root_dir, path) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "startup-state: failed to hash local file {path} for dual-modify check: {error}; treating as conflict"
                );
                let stored_baseline = baseline.and_then(|state| state.get(path));
                let reason = match stored_baseline {
                    None => Some("dual_modify_missing_baseline"),
                    Some(_) => match baseline_hashes.get(path) {
                        Some(baseline_hash) if baseline_hash != remote_hash => {
                            Some("dual_modify_conflict")
                        }
                        _ => None,
                    },
                };

                if let Some(reason) = reason {
                    conflicts.push(StartupConflict {
                        path: path.clone(),
                        reason: reason.to_string(),
                        details_json: json!({
                            "policy": "keep_local_bytes",
                            "local_action": "upload_local",
                            "remote_action": "overwrite_possible",
                        })
                        .to_string(),
                        created_unix_ms: current_unix_ms(),
                    });
                }
                continue;
            }
        };

        let stored_baseline = baseline.and_then(|state| state.get(path));
        let reason = match stored_baseline {
            None => Some("dual_modify_missing_baseline"),
            Some(_) => match baseline_hashes.get(path) {
                Some(baseline_hash) if baseline_hash != remote_hash => Some("dual_modify_conflict"),
                _ => None,
            },
        };

        if local_hash != *remote_hash
            && let Some(reason) = reason
        {
            conflicts.push(StartupConflict {
                path: path.clone(),
                reason: reason.to_string(),
                details_json: json!({
                    "policy": "keep_local_bytes",
                    "local_action": "upload_local",
                    "remote_action": "overwrite_possible",
                })
                .to_string(),
                created_unix_ms: current_unix_ms(),
            });
        }
    }

    conflicts
}

pub fn local_file_content_hash(root_dir: &Path, relative_path: &str) -> Result<String> {
    let absolute = absolute_path(root_dir, relative_path);
    let mut file = File::open(&absolute).with_context(|| {
        format!(
            "failed to open local file for hashing {}",
            absolute.display()
        )
    })?;

    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).with_context(|| {
            format!(
                "failed to read local file for hashing {}",
                absolute.display()
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

pub fn startup_baseline_state_from_remote_index(
    local_state: &LocalTreeState,
    remote_index: &RemoteTreeIndex,
    excluded_paths: &BTreeSet<String>,
) -> LocalTreeState {
    let mut baseline = LocalTreeState::new();

    for path in &remote_index.directories {
        if excluded_paths.contains(path) {
            continue;
        }
        if let Some(entry_state) = local_state.get(path)
            && entry_state.kind == LocalEntryKind::Directory
        {
            baseline.insert(path.clone(), entry_state.clone());
        }
    }

    for path in &remote_index.files {
        if excluded_paths.contains(path) {
            continue;
        }
        if let Some(entry_state) = local_state.get(path)
            && entry_state.kind == LocalEntryKind::File
        {
            baseline.insert(path.clone(), entry_state.clone());
        }
    }

    baseline
}

pub fn parent_directories(path: &str) -> Vec<String> {
    let normalized = normalize_relative_path(path);
    if normalized.is_empty() {
        return Vec::new();
    }

    let segments: Vec<&str> = normalized.split('/').collect();
    let mut directories = Vec::new();
    if segments.len() < 2 {
        return directories;
    }

    for index in 1..segments.len() {
        directories.push(segments[..index].join("/"));
    }
    directories
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalEntryState, local_entry_state_for_path};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn startup_preserve_skips_missing_baseline_file_when_hash_matches_remote() {
        let root = test_root();
        write_file(&root, "docs/readme.txt", b"hello");

        let mut local = LocalTreeState::new();
        local.insert(
            "docs/readme.txt".to_string(),
            local_entry_state_for_path(&root, "docs/readme.txt")
                .unwrap()
                .unwrap(),
        );

        let mut remote_hashes = BTreeMap::new();
        remote_hashes.insert(
            "docs/readme.txt".to_string(),
            local_file_content_hash(&root, "docs/readme.txt").unwrap(),
        );

        let preserve = local_paths_to_preserve_on_startup(&root, &local, None, &remote_hashes);

        assert!(preserve.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_preserve_keeps_missing_baseline_file_when_hash_differs() {
        let root = test_root();
        write_file(&root, "docs/readme.txt", b"hello");

        let mut local = LocalTreeState::new();
        local.insert(
            "docs/readme.txt".to_string(),
            local_entry_state_for_path(&root, "docs/readme.txt")
                .unwrap()
                .unwrap(),
        );

        let mut remote_hashes = BTreeMap::new();
        remote_hashes.insert(
            "docs/readme.txt".to_string(),
            "not-the-local-hash".to_string(),
        );

        let preserve = local_paths_to_preserve_on_startup(&root, &local, None, &remote_hashes);

        assert_eq!(preserve.len(), 1);
        assert!(preserve.contains("docs/readme.txt"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_remote_delete_wins_only_for_unchanged_paths() {
        let root = test_root();
        let mut local = LocalTreeState::new();
        local.insert(
            "unchanged.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 10,
                modified_unix_ms: 100,
            },
        );
        local.insert(
            "changed.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 20,
                modified_unix_ms: 200,
            },
        );

        let mut baseline = LocalTreeState::new();
        baseline.insert(
            "unchanged.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 10,
                modified_unix_ms: 100,
            },
        );
        baseline.insert(
            "changed.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 21,
                modified_unix_ms: 201,
            },
        );

        let remote_files = BTreeSet::new();
        let preserve = BTreeSet::new();
        let baseline_hashes = BTreeMap::new();
        let delete_wins = startup_remote_delete_wins_paths(
            &root,
            &local,
            Some(&baseline),
            &baseline_hashes,
            &remote_files,
            &preserve,
        );

        assert!(delete_wins.contains("unchanged.txt"));
        assert!(!delete_wins.contains("changed.txt"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_dual_modify_detects_missing_baseline_hash_mismatch() {
        let root = test_root();
        write_file(&root, "docs/readme.txt", b"local-version");

        let mut local = LocalTreeState::new();
        local.insert(
            "docs/readme.txt".to_string(),
            local_entry_state_for_path(&root, "docs/readme.txt")
                .unwrap()
                .unwrap(),
        );

        let mut remote_hashes = BTreeMap::new();
        remote_hashes.insert("docs/readme.txt".to_string(), "remote-hash".to_string());

        let preserve = std::iter::once("docs/readme.txt".to_string()).collect();
        let conflicts = startup_dual_modify_conflicts(
            &root,
            &local,
            None,
            &BTreeMap::new(),
            &remote_hashes,
            &preserve,
        );

        assert!(conflicts.iter().any(|conflict| {
            conflict.path == "docs/readme.txt" && conflict.reason == "dual_modify_missing_baseline"
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_dual_modify_detects_conflict_when_remote_hash_differs_from_baseline_hash() {
        let root = test_root();
        write_file(&root, "docs/readme.txt", b"local-version");

        let mut local = LocalTreeState::new();
        local.insert(
            "docs/readme.txt".to_string(),
            local_entry_state_for_path(&root, "docs/readme.txt")
                .unwrap()
                .unwrap(),
        );

        let mut baseline = LocalTreeState::new();
        baseline.insert(
            "docs/readme.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 10,
                modified_unix_ms: 10,
            },
        );
        let mut baseline_hashes = BTreeMap::new();
        baseline_hashes.insert("docs/readme.txt".to_string(), "baseline-hash".to_string());

        let mut remote_hashes = BTreeMap::new();
        remote_hashes.insert("docs/readme.txt".to_string(), "remote-hash".to_string());

        let preserve = std::iter::once("docs/readme.txt".to_string()).collect();
        let conflicts = startup_dual_modify_conflicts(
            &root,
            &local,
            Some(&baseline),
            &baseline_hashes,
            &remote_hashes,
            &preserve,
        );

        assert!(conflicts.iter().any(|conflict| {
            conflict.path == "docs/readme.txt" && conflict.reason == "dual_modify_conflict"
        }));

        fs::remove_dir_all(root).unwrap();
    }

    fn write_file(root: &std::path::Path, relative_path: &str, bytes: &[u8]) {
        let absolute = root.join(relative_path);
        if let Some(parent) = absolute.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(absolute, bytes).unwrap();
    }

    fn test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut root = std::env::temp_dir();
        root.push(format!(
            "ironmesh-folder-agent-startup-test-{}-{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }
}
