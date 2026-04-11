mod folder_agent_conflicts;
mod folder_agent_runtime;
mod folder_agent_startup;
mod folder_agent_state;
mod folder_agent_ui;

pub use folder_agent_conflicts::*;
pub use folder_agent_runtime::*;
pub use folder_agent_startup::*;
pub use folder_agent_state::*;
pub use folder_agent_ui::*;

use anyhow::{Context, Result, anyhow};
use client_sdk::{
    ClientIdentityMaterial, ConnectionBootstrap, IronMeshClient, build_http_client_from_pem,
    build_http_client_with_identity_from_pem, normalize_server_base_url,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use sync_core::{EntryKind, SyncSnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEntryState {
    pub kind: LocalEntryKind,
    pub size_bytes: u64,
    pub modified_unix_ms: u128,
}

impl LocalEntryState {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        let kind = if metadata.is_dir() {
            LocalEntryKind::Directory
        } else {
            LocalEntryKind::File
        };

        let modified_unix_ms = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_millis())
            .unwrap_or(0);

        Self {
            kind,
            size_bytes: metadata.len(),
            modified_unix_ms,
        }
    }
}

pub type LocalTreeState = BTreeMap<String, LocalEntryState>;

pub fn build_configured_client(
    server_base_url: Option<&str>,
    client_bootstrap_json: Option<&str>,
    server_ca_pem: Option<&str>,
    client_identity_json: Option<&str>,
) -> Result<IronMeshClient> {
    let server_ca_pem = normalized_optional_string(server_ca_pem);
    let client_bootstrap_json = normalized_optional_string(client_bootstrap_json);
    let client_identity_json = normalized_optional_string(client_identity_json);
    let client_identity = client_identity_json
        .as_deref()
        .map(ClientIdentityMaterial::from_json_str)
        .transpose()
        .context("failed to parse client identity JSON")?;
    if let Some(raw) = client_bootstrap_json.as_deref() {
        let mut bootstrap = ConnectionBootstrap::from_json_str(raw)
            .context("failed to parse connection bootstrap JSON")?;
        if let Some(server_ca_pem) = server_ca_pem.as_ref() {
            bootstrap.trust_roots.public_api_ca_pem = Some(server_ca_pem.clone());
        }
        return match client_identity.as_ref() {
            Some(identity) => bootstrap.build_client_with_identity(identity),
            None => bootstrap.build_client(),
        };
    }

    let server_base_url = server_base_url
        .ok_or_else(|| anyhow!("missing server_base_url or client_bootstrap_json"))?;
    match client_identity.as_ref() {
        Some(identity) => build_http_client_with_identity_from_pem(
            server_ca_pem.as_deref(),
            server_base_url,
            identity,
        ),
        None => build_http_client_from_pem(server_ca_pem.as_deref(), server_base_url),
    }
}

pub fn describe_connection_target(
    server_base_url: Option<&str>,
    client_bootstrap_json: Option<&str>,
) -> Result<String> {
    if let Some(raw) = normalized_optional_string(client_bootstrap_json) {
        let bootstrap = ConnectionBootstrap::from_json_str(&raw)
            .context("failed to parse connection bootstrap JSON")?;
        return bootstrap.connection_target_label();
    }

    let server_base_url = server_base_url
        .ok_or_else(|| anyhow!("missing server_base_url or client_bootstrap_json"))?;
    Ok(normalize_server_base_url(server_base_url)?.to_string())
}

pub(crate) fn normalized_optional_string(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalTreeDiff {
    pub created_directories: Vec<String>,
    pub created_or_modified_files: Vec<String>,
    pub deleted_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteTreeIndex {
    pub directories: BTreeSet<String>,
    pub files: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalTreeScanProgress {
    pub scanned_entry_count: u64,
    pub scanned_directory_count: u64,
    pub pending_directory_count: u64,
    pub current_path: Option<String>,
}

pub fn scan_local_tree(root: &Path) -> Result<LocalTreeState> {
    scan_local_tree_with_progress(root, |_| {})
}

pub fn scan_local_tree_with_progress<F>(root: &Path, mut on_progress: F) -> Result<LocalTreeState>
where
    F: FnMut(&LocalTreeScanProgress),
{
    if !root.exists() {
        on_progress(&LocalTreeScanProgress::default());
        return Ok(LocalTreeState::new());
    }

    let mut state = LocalTreeState::new();
    let mut pending = vec![root.to_path_buf()];
    let mut progress = LocalTreeScanProgress {
        pending_directory_count: 1,
        current_path: Some("<root>".to_string()),
        ..LocalTreeScanProgress::default()
    };
    on_progress(&progress);

    while let Some(directory) = pending.pop() {
        progress.scanned_directory_count = progress.scanned_directory_count.saturating_add(1);
        progress.pending_directory_count = (pending.len() + 1).try_into().unwrap_or(u64::MAX);
        progress.current_path = relative_path(root, &directory).or(Some("<root>".to_string()));
        on_progress(&progress);

        let entries = fs::read_dir(&directory)
            .with_context(|| format!("failed to read local directory {}", directory.display()))?;

        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "failed to read local directory entry under {}",
                    directory.display()
                )
            })?;

            let path = entry.path();
            let Some(relative) = relative_path(root, &path) else {
                continue;
            };

            let metadata = entry
                .metadata()
                .with_context(|| format!("failed to read metadata for {}", path.display()))?;

            progress.scanned_entry_count = progress.scanned_entry_count.saturating_add(1);
            progress.current_path = Some(relative.clone());

            if metadata.is_dir() {
                pending.push(path.clone());
            }

            progress.pending_directory_count = pending.len().try_into().unwrap_or(u64::MAX);
            on_progress(&progress);

            if is_ironmesh_internal_relative_path(&relative) {
                continue;
            }

            state.insert(relative, LocalEntryState::from_metadata(&metadata));
        }
    }

    progress.pending_directory_count = 0;
    progress.current_path = None;
    on_progress(&progress);

    Ok(state)
}

fn is_ironmesh_internal_relative_path(relative_path: &str) -> bool {
    relative_path.split('/').any(|segment| {
        segment == ".ironmesh"
            || segment == ".ironmesh-conflicts"
            || segment.contains(".ironmesh-part-")
    })
}

pub(crate) fn transfer_state_root(root_dir: &Path) -> PathBuf {
    root_dir.join(".ironmesh").join("transfers")
}

pub(crate) fn transfer_path_stem(remote_key: &str) -> String {
    blake3::hash(remote_key.as_bytes()).to_hex().to_string()
}

pub(crate) fn upload_transfer_state_path(root_dir: &Path, remote_key: &str) -> PathBuf {
    transfer_state_root(root_dir)
        .join("uploads")
        .join(format!("{}.json", transfer_path_stem(remote_key)))
}

pub(crate) fn download_transfer_state_path(root_dir: &Path, remote_key: &str) -> PathBuf {
    transfer_state_root(root_dir)
        .join("downloads")
        .join(format!("{}.json", transfer_path_stem(remote_key)))
}

pub(crate) fn download_transfer_temp_path(root_dir: &Path, remote_key: &str) -> PathBuf {
    transfer_state_root(root_dir)
        .join("downloads")
        .join(format!("{}.part", transfer_path_stem(remote_key)))
}

pub fn local_entry_state_for_path(
    root: &Path,
    relative_path: impl AsRef<str>,
) -> Result<Option<LocalEntryState>> {
    let normalized = normalize_relative_path(relative_path.as_ref());
    if normalized.is_empty() {
        return Ok(None);
    }

    let absolute = root.join(&normalized);
    match fs::metadata(&absolute) {
        Ok(metadata) => Ok(Some(LocalEntryState::from_metadata(&metadata))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("failed to read metadata for {}", absolute.display())),
    }
}

pub fn diff_local_trees(previous: &LocalTreeState, current: &LocalTreeState) -> LocalTreeDiff {
    let mut created_directories = Vec::new();
    let mut created_or_modified_files = Vec::new();
    let mut deleted_paths = Vec::new();

    let mut all_paths = BTreeSet::new();
    all_paths.extend(previous.keys().cloned());
    all_paths.extend(current.keys().cloned());

    for path in all_paths {
        let previous_entry = previous.get(&path);
        let current_entry = current.get(&path);

        match (previous_entry, current_entry) {
            (None, Some(current_entry)) => match current_entry.kind {
                LocalEntryKind::Directory => created_directories.push(path),
                LocalEntryKind::File => created_or_modified_files.push(path),
            },
            (Some(previous_entry), Some(current_entry)) if previous_entry != current_entry => {
                match current_entry.kind {
                    LocalEntryKind::Directory => created_directories.push(path),
                    LocalEntryKind::File => created_or_modified_files.push(path),
                }
            }
            (Some(_), None) => deleted_paths.push(path),
            _ => {}
        }
    }

    LocalTreeDiff {
        created_directories,
        created_or_modified_files,
        deleted_paths,
    }
}

pub fn build_remote_index(snapshot: &SyncSnapshot) -> RemoteTreeIndex {
    let mut index = RemoteTreeIndex::default();

    for entry in &snapshot.remote {
        let path = normalize_relative_path(&entry.path);
        if path.is_empty() {
            continue;
        }

        match entry.kind {
            EntryKind::Directory => {
                index.directories.insert(path);
            }
            EntryKind::File => {
                index.files.insert(path);
            }
        }
    }

    index
}

pub fn remote_entry_kinds(snapshot: &SyncSnapshot) -> BTreeMap<String, EntryKind> {
    let mut result = BTreeMap::new();
    for entry in &snapshot.remote {
        let path = normalize_relative_path(&entry.path);
        if path.is_empty() {
            continue;
        }
        result.insert(path, entry.kind);
    }
    result
}

pub fn normalize_relative_path(path: &str) -> String {
    path.trim()
        .trim_matches('/')
        .replace('\\', "/")
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }

    let lossy = relative.to_string_lossy();
    let normalized = normalize_relative_path(&lossy);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub fn absolute_path(root: &Path, relative_path: &str) -> PathBuf {
    root.join(normalize_relative_path(relative_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sync_core::NamespaceEntry;

    #[test]
    fn diff_local_trees_detects_creates_updates_and_deletes() {
        let mut previous = LocalTreeState::new();
        previous.insert(
            "docs/readme.md".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 10,
                modified_unix_ms: 10,
            },
        );
        previous.insert(
            "tmp".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::Directory,
                size_bytes: 0,
                modified_unix_ms: 10,
            },
        );

        let mut current = LocalTreeState::new();
        current.insert(
            "docs/readme.md".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 11,
                modified_unix_ms: 20,
            },
        );
        current.insert(
            "docs/new".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::Directory,
                size_bytes: 0,
                modified_unix_ms: 20,
            },
        );

        let diff = diff_local_trees(&previous, &current);

        assert_eq!(diff.created_directories, vec!["docs/new".to_string()]);
        assert_eq!(
            diff.created_or_modified_files,
            vec!["docs/readme.md".to_string()]
        );
        assert_eq!(diff.deleted_paths, vec!["tmp".to_string()]);
    }

    #[test]
    fn build_remote_index_separates_directories_and_files() {
        let snapshot = SyncSnapshot {
            local: Vec::new(),
            remote: vec![
                NamespaceEntry::directory("docs/"),
                NamespaceEntry::file("docs/readme.md", "v1", "h1"),
            ],
        };

        let index = build_remote_index(&snapshot);

        assert!(index.directories.contains("docs"));
        assert!(index.files.contains("docs/readme.md"));
    }

    #[test]
    fn scan_local_tree_returns_relative_paths() {
        let root = test_root();
        fs::create_dir_all(root.join("nested")).expect("directory should be created");
        fs::write(root.join("nested/file.txt"), b"hello").expect("file should be written");

        let state = scan_local_tree(&root).expect("scan should succeed");

        assert!(state.contains_key("nested"));
        assert!(state.contains_key("nested/file.txt"));

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn scan_local_tree_ignores_ironmesh_internal_artifacts() {
        let root = test_root();
        fs::create_dir_all(root.join(".ironmesh-conflicts/remote/nested"))
            .expect("internal directory should be created");
        fs::write(
            root.join(".ironmesh-conflicts/remote/nested/conflict.txt"),
            b"do-not-sync",
        )
        .expect("internal file should be written");
        fs::write(root.join(".file.ironmesh-part-123"), b"partial")
            .expect("partial file should be written");
        fs::write(root.join("keep.txt"), b"keep").expect("regular file should be written");

        let state = scan_local_tree(&root).expect("scan should succeed");

        assert!(state.contains_key("keep.txt"));
        assert!(!state.contains_key(".file.ironmesh-part-123"));
        assert!(
            !state
                .keys()
                .any(|path| path.starts_with(".ironmesh-conflicts"))
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn scan_local_tree_with_progress_reports_entries_and_completion() {
        let root = test_root();
        fs::create_dir_all(root.join("nested/inner")).expect("directory should be created");
        fs::write(root.join("nested/file.txt"), b"hello").expect("file should be written");

        let mut progress_updates = Vec::new();
        let state = scan_local_tree_with_progress(&root, |progress| {
            progress_updates.push(progress.clone());
        })
        .expect("scan should succeed");

        assert!(state.contains_key("nested"));
        assert!(state.contains_key("nested/inner"));
        assert!(state.contains_key("nested/file.txt"));
        assert!(!progress_updates.is_empty());
        assert!(progress_updates.iter().any(|progress| progress.scanned_entry_count >= 3));
        assert_eq!(
            progress_updates.last().map(|progress| progress.pending_directory_count),
            Some(0)
        );
        assert_eq!(
            progress_updates.last().and_then(|progress| progress.current_path.clone()),
            None
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    fn test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let mut root = std::env::temp_dir();
        root.push(format!(
            "ironmesh-sync-agent-core-test-{}-{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&root).expect("temp root should be created");
        root
    }
}
