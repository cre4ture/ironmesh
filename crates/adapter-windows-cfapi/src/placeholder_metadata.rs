#![cfg(windows)]

use crate::auth::is_internal_client_identity_relative_path;
use crate::cfapi::{
    cf_ensure_placeholder_identity, cf_get_placeholder_standard_info_with_identity,
    cf_update_placeholder_file_identity, cf_update_placeholder_file_identity_with_oplock,
    describe_path_state, open_sync_path, path_is_placeholder,
};
use crate::connection_config::is_internal_connection_bootstrap_relative_path;
use crate::content_fingerprint::file_content_fingerprint;
use crate::helpers::{
    PlaceholderFileIdentity, decode_placeholder_file_identity, normalize_path, path_to_relative,
};
use crate::snapshot_cache::is_internal_remote_snapshot_relative_path;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use sync_core::{EntryKind, SyncSnapshot};
use uuid::Uuid;
use walkdir::WalkDir;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RemoteDeleteReconcileReport {
    pub deleted_paths: BTreeSet<String>,
    pub preserved_paths: BTreeSet<String>,
    pub suppressed_startup_paths: BTreeSet<String>,
}

pub fn record_in_sync_local_file_state(
    sync_root_path: &Path,
    relative_path: &str,
    provider_instance_id: Uuid,
) -> Result<()> {
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

    let clean_content_fingerprint = file_content_fingerprint(&full_path)?;
    record_in_sync_content_fingerprint(
        sync_root_path,
        &normalized,
        provider_instance_id,
        &clean_content_fingerprint,
    )
}

pub fn record_in_sync_content_fingerprint(
    sync_root_path: &Path,
    relative_path: &str,
    provider_instance_id: Uuid,
    clean_content_fingerprint: &str,
) -> Result<()> {
    let normalized = normalize_path(relative_path);
    if normalized.is_empty() || is_internal_sync_root_relative_path(&normalized) {
        return Ok(());
    }

    mutate_placeholder_identity_for_path(sync_root_path, &normalized, |identity| {
        identity.path = normalized.clone();
        identity.provider_instance_id = Some(provider_instance_id);
        if identity.remote_content_fingerprint.is_none() {
            identity.remote_content_fingerprint = Some(clean_content_fingerprint.to_string());
        }
        identity.clean_content_fingerprint = Some(clean_content_fingerprint.to_string());
    })
}

pub fn record_in_sync_remote_file_state(
    sync_root_path: &Path,
    relative_path: &str,
    provider_instance_id: Uuid,
) -> Result<()> {
    let normalized = normalize_path(relative_path);
    if normalized.is_empty() || is_internal_sync_root_relative_path(&normalized) {
        return Ok(());
    }

    mutate_placeholder_identity_for_path(sync_root_path, &normalized, |identity| {
        identity.path = normalized.clone();
        identity.provider_instance_id = Some(provider_instance_id);
        if let Some(remote_content_fingerprint) = identity.remote_content_fingerprint.clone() {
            identity.clean_content_fingerprint = Some(remote_content_fingerprint);
        }
    })
}

pub fn refresh_remote_placeholder_state(
    sync_root_path: &Path,
    relative_path: &str,
    provider_instance_id: Uuid,
    remote_version: Option<&str>,
    remote_content_hash: Option<&str>,
    remote_size_bytes: Option<u64>,
    remote_content_fingerprint: Option<&str>,
) -> Result<()> {
    let normalized = normalize_path(relative_path);
    if normalized.is_empty() || is_internal_sync_root_relative_path(&normalized) {
        return Ok(());
    }

    let full_path = sync_root_path.join(normalized.replace('/', "\\"));
    let metadata = match fs::metadata(&full_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to inspect {}", full_path.display()));
        }
    };
    if metadata.is_dir() {
        return Ok(());
    }

    mutate_placeholder_identity_for_path(sync_root_path, &normalized, |identity| {
        identity.path = normalized.clone();
        identity.provider_instance_id = Some(provider_instance_id);
        identity.remote_version = remote_version
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        identity.remote_content_hash = remote_content_hash
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        identity.remote_content_fingerprint = remote_content_fingerprint
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        identity.remote_size_bytes = remote_size_bytes;
    })
}

pub fn reconcile_remote_delete_state(
    sync_root_path: &Path,
    current_snapshot: &SyncSnapshot,
    provider_instance_id: Uuid,
) -> Result<RemoteDeleteReconcileReport> {
    let current_remote_files = current_remote_file_paths(current_snapshot);
    let current_remote_directories = current_remote_directory_paths(current_snapshot);
    let mut report = RemoteDeleteReconcileReport::default();
    let mut local_file_candidates = Vec::new();

    for entry in WalkDir::new(sync_root_path)
        .min_depth(1)
        .into_iter()
        .flatten()
    {
        if entry.file_type().is_dir() {
            continue;
        }
        let relative_path = path_to_relative(sync_root_path, &entry.path().to_string_lossy());
        if relative_path.is_empty()
            || is_internal_sync_root_relative_path(&relative_path)
            || current_remote_files.contains(relative_path.as_str())
        {
            continue;
        }
        local_file_candidates.push((relative_path, entry.into_path()));
    }

    local_file_candidates.sort_by(|(left, _), (right, _)| {
        right
            .matches('/')
            .count()
            .cmp(&left.matches('/').count())
            .then_with(|| right.cmp(left))
    });

    for (relative_path, full_path) in local_file_candidates {
        let file = match open_sync_path(&full_path, false) {
            Ok(file) => file,
            Err(_) => {
                report.preserved_paths.insert(relative_path);
                continue;
            }
        };
        let placeholder_info = match cf_get_placeholder_standard_info_with_identity(&file) {
            Ok(info) => info,
            Err(_) => {
                report.preserved_paths.insert(relative_path);
                continue;
            }
        };
        let Some(identity) = decode_placeholder_file_identity(placeholder_info.file_identity())
        else {
            report.preserved_paths.insert(relative_path);
            continue;
        };
        if identity.path != relative_path
            || identity.provider_instance_id != Some(provider_instance_id)
            || !identity_has_remote_baseline(&identity)
        {
            report.preserved_paths.insert(relative_path);
            continue;
        }

        let clean_local = if placeholder_info.info().ModifiedDataSize == 0 {
            true
        } else if let Some(clean_content_fingerprint) =
            identity.clean_content_fingerprint.as_deref()
        {
            file_content_fingerprint(&full_path)
                .map(|current_fingerprint| current_fingerprint == clean_content_fingerprint)
                .unwrap_or(false)
        } else {
            false
        };
        if !clean_local {
            report.preserved_paths.insert(relative_path);
            continue;
        }

        match fs::remove_file(&full_path) {
            Ok(()) => {
                report.deleted_paths.insert(relative_path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                report.suppressed_startup_paths.insert(relative_path);
            }
        }
    }

    let mut local_directory_candidates = Vec::new();
    for entry in WalkDir::new(sync_root_path)
        .min_depth(1)
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_dir() {
            continue;
        }
        let relative_path = path_to_relative(sync_root_path, &entry.path().to_string_lossy());
        if relative_path.is_empty()
            || is_internal_sync_root_relative_path(&relative_path)
            || current_remote_directories.contains(relative_path.as_str())
        {
            continue;
        }
        local_directory_candidates.push((relative_path, entry.into_path()));
    }

    local_directory_candidates.sort_by(|(left, _), (right, _)| {
        right
            .matches('/')
            .count()
            .cmp(&left.matches('/').count())
            .then_with(|| right.cmp(left))
    });

    for (relative_path, full_path) in local_directory_candidates {
        let file = match open_sync_path(&full_path, false) {
            Ok(file) => file,
            Err(_) => {
                report.preserved_paths.insert(relative_path);
                continue;
            }
        };
        let placeholder_info = match cf_get_placeholder_standard_info_with_identity(&file) {
            Ok(info) => info,
            Err(_) => {
                report.preserved_paths.insert(relative_path);
                continue;
            }
        };
        let Some(identity) = decode_placeholder_file_identity(placeholder_info.file_identity())
        else {
            report.preserved_paths.insert(relative_path);
            continue;
        };
        if identity.path != relative_path
            || !matches!(
                identity.provider_instance_id,
                Some(identity_provider) if identity_provider == provider_instance_id
            ) && identity.provider_instance_id.is_some()
        {
            report.preserved_paths.insert(relative_path);
            continue;
        }

        let state_before = describe_path_state(&full_path);
        match fs::remove_dir(&full_path) {
            Ok(()) => {
                tracing::info!(
                    "remote-delete-reconcile: removed stale remote-managed directory {} state_before={}",
                    full_path.display(),
                    state_before
                );
                report.deleted_paths.insert(relative_path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                tracing::info!(
                    "remote-delete-reconcile: preserved non-empty stale directory {} error={} state={}",
                    full_path.display(),
                    error,
                    state_before
                );
                report.preserved_paths.insert(relative_path);
            }
            Err(error) => {
                tracing::info!(
                    "remote-delete-reconcile: failed to remove stale remote-managed directory {} error={} state={}",
                    full_path.display(),
                    error,
                    state_before
                );
                report.suppressed_startup_paths.insert(relative_path);
            }
        }
    }

    Ok(report)
}

fn mutate_placeholder_identity_for_path(
    sync_root_path: &Path,
    relative_path: &str,
    mutator: impl FnOnce(&mut PlaceholderFileIdentity),
) -> Result<()> {
    let full_path = sync_root_path.join(relative_path.replace('/', "\\"));
    let file = open_sync_path(&full_path, false).with_context(|| {
        format!(
            "failed to open {} for placeholder metadata read",
            full_path.display()
        )
    })?;

    let mut identity = match cf_get_placeholder_standard_info_with_identity(&file) {
        Ok(info) => decode_placeholder_file_identity(info.file_identity())
            .unwrap_or_else(|| PlaceholderFileIdentity::new(relative_path)),
        Err(_) => PlaceholderFileIdentity::new(relative_path),
    };
    let original_identity = identity.clone();
    mutator(&mut identity);
    if identity == original_identity {
        return Ok(());
    }
    let encoded = identity.encoded();

    match cf_update_placeholder_file_identity_with_oplock(&full_path, &encoded) {
        Ok(()) => Ok(()),
        Err(oplock_err) => {
            if path_is_placeholder(&full_path) {
                return Err(oplock_err).with_context(|| {
                    format!(
                        "refusing to reopen existing placeholder {} with generic write access after oplock metadata update failed",
                        full_path.display()
                    )
                });
            }
            let writable_file = open_sync_path(&full_path, true).with_context(|| {
                format!(
                    "failed to reopen {} for placeholder metadata update fallback",
                    full_path.display()
                )
            })?;
            cf_ensure_placeholder_identity(&writable_file, relative_path)?;
            cf_update_placeholder_file_identity(&writable_file, &encoded)
        }
    }
}

fn current_remote_file_paths(snapshot: &SyncSnapshot) -> BTreeSet<String> {
    snapshot
        .remote
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
        .map(|entry| normalize_path(&entry.path))
        .collect()
}

fn current_remote_directory_paths(snapshot: &SyncSnapshot) -> BTreeSet<String> {
    let mut directories = BTreeSet::new();

    for entry in &snapshot.remote {
        let normalized = normalize_path(&entry.path);
        if normalized.is_empty() {
            continue;
        }

        if entry.kind == EntryKind::Directory {
            directories.insert(normalized.clone());
        }

        let segments = normalized
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        let limit = match entry.kind {
            EntryKind::Directory => segments.len(),
            EntryKind::File => segments.len().saturating_sub(1),
        };
        for depth in 1..=limit {
            directories.insert(segments[..depth].join("/"));
        }
    }

    directories
}

fn identity_has_remote_baseline(identity: &PlaceholderFileIdentity) -> bool {
    identity.remote_version.is_some()
        || identity.remote_content_hash.is_some()
        || identity.remote_content_fingerprint.is_some()
        || identity.remote_size_bytes.is_some()
        || identity.clean_content_fingerprint.is_some()
}

fn is_internal_sync_root_relative_path(path: &str) -> bool {
    is_internal_client_identity_relative_path(path)
        || is_internal_connection_bootstrap_relative_path(path)
        || is_internal_remote_snapshot_relative_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync_core::NamespaceEntry;

    #[test]
    fn reconcile_remote_delete_preserves_local_only_plain_files() {
        let sync_root =
            std::env::temp_dir().join(format!("ironmesh-placeholder-meta-{}", Uuid::now_v7()));
        fs::create_dir_all(&sync_root).expect("sync root should exist");
        let full_path = sync_root.join("notes.txt");
        fs::write(&full_path, b"offline local").expect("local file should exist");

        let report = reconcile_remote_delete_state(
            &sync_root,
            &SyncSnapshot {
                local: Vec::new(),
                remote: vec![NamespaceEntry::file("other.txt", "v1", "h1")],
            },
            Uuid::now_v7(),
        )
        .expect("reconcile should succeed");

        assert!(report.deleted_paths.is_empty());
        assert!(report.preserved_paths.contains("notes.txt"));

        let _ = fs::remove_dir_all(sync_root);
    }
}
