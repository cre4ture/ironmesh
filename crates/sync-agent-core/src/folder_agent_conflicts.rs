use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use client_sdk::IronMeshClient;
use common::content_fingerprint::file_content_fingerprint;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::{
    ModificationLogContext, ModificationLogStore, ModificationOperation, ModificationOutcome,
    ModificationPhase, ModificationTriggerSource, PathScope, StartupStateStore, absolute_path,
    build_configured_client, conflict_copy_dir, copy_file_atomically, current_unix_ms,
    delete_conflict_copies, describe_connection_target, local_entry_state_for_path,
    newest_remote_conflict_copy, normalize_relative_path, try_record_modification,
    upload_transfer_state_path,
};

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictResolutionStrategy {
    KeepLocal,
    KeepRemote,
}

#[derive(Debug, Serialize)]
pub struct ConflictResolutionResult {
    pub path: String,
    pub strategy: ConflictResolutionStrategy,
    pub conflict_reason: Option<String>,
    pub action: String,
    pub removed_conflict_rows: usize,
    pub removed_conflict_copy_files: usize,
}

pub fn validate_user_relative_path_input(path: &str) -> Result<String> {
    let normalized = normalize_relative_path(path);
    if normalized.is_empty() {
        bail!("path must not be empty");
    }

    for segment in normalized.split('/') {
        if segment == ".." {
            bail!("path must not contain '..' segments");
        }
        if segment.contains(':') {
            bail!("path must not contain ':' characters");
        }
    }

    Ok(normalized)
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_conflict_action(
    root_dir: &Path,
    server_base_url: Option<&str>,
    client_bootstrap_json: Option<&str>,
    server_ca_pem: Option<&str>,
    client_identity_json: Option<&str>,
    scope: &PathScope,
    state_store: &StartupStateStore,
    path: &str,
    strategy: ConflictResolutionStrategy,
    delete_conflict_copies_on_finish: bool,
) -> Result<ConflictResolutionResult> {
    let normalized_path = validate_user_relative_path_input(path)?;

    match strategy {
        ConflictResolutionStrategy::KeepLocal => {
            let removed_conflict_rows = state_store.remove_conflict(normalized_path.as_str())?;
            let removed_conflict_copy_files = if delete_conflict_copies_on_finish {
                delete_conflict_copies(root_dir, normalized_path.as_str()).unwrap_or(0)
            } else {
                0
            };
            Ok(ConflictResolutionResult {
                path: normalized_path,
                strategy,
                conflict_reason: None,
                action: "cleared_conflict_row".to_string(),
                removed_conflict_rows,
                removed_conflict_copy_files,
            })
        }
        ConflictResolutionStrategy::KeepRemote => {
            let connection_target =
                describe_connection_target(server_base_url, client_bootstrap_json)
                    .context("failed to resolve connection target for conflict resolution")?;
            let modification_log_store = ModificationLogStore::from_state_store(
                state_store,
                root_dir,
                scope,
                &connection_target,
            );
            let modification_context = ModificationLogContext::new(
                ModificationPhase::Manual,
                ModificationTriggerSource::ConflictResolution,
            );
            let conflict = state_store
                .load_conflict(normalized_path.as_str())?
                .with_context(|| format!("conflict not found for path={normalized_path}"))?;

            match conflict.reason.as_str() {
                "dual_modify_conflict" | "dual_modify_missing_baseline" => {
                    let remote_copy =
                        newest_remote_conflict_copy(root_dir, normalized_path.as_str())?;

                    let local_target = absolute_path(root_dir, normalized_path.as_str());
                    preserve_local_conflict_copy(
                        root_dir,
                        normalized_path.as_str(),
                        &local_target,
                    )?;

                    copy_file_atomically(&remote_copy, &local_target).with_context(|| {
                        format!(
                            "failed to apply remote conflict copy {} into {}",
                            remote_copy.display(),
                            local_target.display()
                        )
                    })?;

                    let client = build_configured_client(
                        server_base_url,
                        client_bootstrap_json,
                        server_ca_pem,
                        client_identity_json,
                    )?;
                    let metadata = fs::metadata(&local_target).with_context(|| {
                        format!(
                            "failed to inspect resolved local file {}",
                            local_target.display()
                        )
                    })?;
                    let content_hash = upload_local_file(
                        root_dir,
                        &client,
                        scope,
                        normalized_path.as_str(),
                        metadata.len(),
                        Some(&modification_log_store),
                        Some(&modification_context),
                    )?;

                    if let Some(entry_state) =
                        local_entry_state_for_path(root_dir, normalized_path.as_str())?
                    {
                        state_store.upsert_baseline_entry_with_hash(
                            normalized_path.as_str(),
                            &entry_state,
                            Some(content_hash.as_str()),
                        )?;
                    }

                    let removed_conflict_rows =
                        state_store.remove_conflict(normalized_path.as_str())?;
                    let removed_conflict_copy_files = if delete_conflict_copies_on_finish {
                        delete_conflict_copies(root_dir, normalized_path.as_str()).unwrap_or(0)
                    } else {
                        0
                    };

                    Ok(ConflictResolutionResult {
                        path: normalized_path,
                        strategy,
                        conflict_reason: Some(conflict.reason),
                        action: "applied_remote_copy_and_uploaded".to_string(),
                        removed_conflict_rows,
                        removed_conflict_copy_files,
                    })
                }
                "modify_delete_conflict" | "add_delete_ambiguous_missing_baseline" => {
                    let local_target = absolute_path(root_dir, normalized_path.as_str());
                    preserve_local_conflict_copy(
                        root_dir,
                        normalized_path.as_str(),
                        &local_target,
                    )?;

                    let remote_key = scope
                        .local_to_remote(normalized_path.as_str())
                        .unwrap_or_else(|| normalized_path.clone());
                    remove_local_path(
                        root_dir,
                        normalized_path.as_str(),
                        Some(remote_key.as_str()),
                        Some(&modification_log_store),
                        Some(&modification_context),
                    )?;

                    let client = build_configured_client(
                        server_base_url,
                        client_bootstrap_json,
                        server_ca_pem,
                        client_identity_json,
                    )?;
                    delete_remote_file(
                        &client,
                        scope,
                        normalized_path.as_str(),
                        Some(&modification_log_store),
                        Some(&modification_context),
                    )?;
                    state_store.remove_baseline_entry(normalized_path.as_str())?;

                    let removed_conflict_rows =
                        state_store.remove_conflict(normalized_path.as_str())?;
                    let removed_conflict_copy_files = if delete_conflict_copies_on_finish {
                        delete_conflict_copies(root_dir, normalized_path.as_str()).unwrap_or(0)
                    } else {
                        0
                    };

                    Ok(ConflictResolutionResult {
                        path: normalized_path,
                        strategy,
                        conflict_reason: Some(conflict.reason),
                        action: "deleted_local_and_tombstoned_remote".to_string(),
                        removed_conflict_rows,
                        removed_conflict_copy_files,
                    })
                }
                other => bail!("unsupported conflict reason for keep-remote resolution: {other}"),
            }
        }
    }
}

pub fn upload_local_file(
    root_dir: &Path,
    client: &IronMeshClient,
    scope: &PathScope,
    relative_path: &str,
    _size_bytes: u64,
    modification_log: Option<&ModificationLogStore>,
    modification_context: Option<&ModificationLogContext>,
) -> Result<String> {
    let absolute = absolute_path(root_dir, relative_path);
    let content_hash = file_content_hash(&absolute)?;

    let remote_key = scope.local_to_remote(relative_path).ok_or_else(|| {
        anyhow::anyhow!("refusing to upload local root without concrete scoped path")
    })?;
    let state_path = upload_transfer_state_path(root_dir, &remote_key);

    let result = client.put_file_resumable(remote_key.clone(), &absolute, &state_path);
    if let Err(error) = result {
        let error = error.context(format!(
            "failed to upload local file {relative_path} to {remote_key}"
        ));
        try_record_modification(
            modification_log,
            modification_context,
            ModificationOperation::Upload,
            ModificationOutcome::Error,
            relative_path,
            remote_key.as_str(),
            Some(_size_bytes),
            Some(content_hash.as_str()),
            Some(&format!("{error:#}")),
        );
        return Err(error);
    }

    try_record_modification(
        modification_log,
        modification_context,
        ModificationOperation::Upload,
        ModificationOutcome::Success,
        relative_path,
        remote_key.as_str(),
        Some(_size_bytes),
        Some(content_hash.as_str()),
        None,
    );

    Ok(content_hash)
}

pub fn delete_remote_file(
    client: &IronMeshClient,
    scope: &PathScope,
    file_path: &str,
    modification_log: Option<&ModificationLogStore>,
    modification_context: Option<&ModificationLogContext>,
) -> Result<()> {
    let Some(remote_key) = scope.local_to_remote(file_path) else {
        return Ok(());
    };

    let result = client.delete_path_blocking(&remote_key);
    if let Err(error) = result {
        let error = error.context(format!("failed to delete remote file {remote_key}"));
        try_record_modification(
            modification_log,
            modification_context,
            ModificationOperation::DeleteRemote,
            ModificationOutcome::Error,
            file_path,
            remote_key.as_str(),
            None,
            None,
            Some(&format!("{error:#}")),
        );
        return Err(error);
    }

    try_record_modification(
        modification_log,
        modification_context,
        ModificationOperation::DeleteRemote,
        ModificationOutcome::Success,
        file_path,
        remote_key.as_str(),
        None,
        None,
        None,
    );

    Ok(())
}

pub fn remove_local_path(
    root_dir: &Path,
    relative_path: &str,
    remote_key: Option<&str>,
    modification_log: Option<&ModificationLogStore>,
    modification_context: Option<&ModificationLogContext>,
) -> Result<()> {
    let absolute = absolute_path(root_dir, relative_path);
    let resolved_remote_key = remote_key.unwrap_or(relative_path);

    match fs::metadata(&absolute) {
        Ok(metadata) => {
            if metadata.is_dir() {
                if let Err(error) = fs::remove_dir_all(&absolute) {
                    let error = anyhow::Error::from(error).context(format!(
                        "failed to remove local directory {}",
                        absolute.display()
                    ));
                    try_record_modification(
                        modification_log,
                        modification_context,
                        ModificationOperation::DeleteLocal,
                        ModificationOutcome::Error,
                        relative_path,
                        resolved_remote_key,
                        None,
                        None,
                        Some(&format!("{error:#}")),
                    );
                    return Err(error);
                }
            } else {
                if let Err(error) = fs::remove_file(&absolute) {
                    let error = anyhow::Error::from(error).context(format!(
                        "failed to remove local file {}",
                        absolute.display()
                    ));
                    try_record_modification(
                        modification_log,
                        modification_context,
                        ModificationOperation::DeleteLocal,
                        ModificationOutcome::Error,
                        relative_path,
                        resolved_remote_key,
                        None,
                        None,
                        Some(&format!("{error:#}")),
                    );
                    return Err(error);
                }
            }

            try_record_modification(
                modification_log,
                modification_context,
                ModificationOperation::DeleteLocal,
                ModificationOutcome::Success,
                relative_path,
                resolved_remote_key,
                None,
                None,
                None,
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect local path {}", absolute.display()));
        }
    }

    Ok(())
}

fn file_content_hash(path: &Path) -> Result<String> {
    file_content_fingerprint(path).with_context(|| {
        format!(
            "failed to compute local content fingerprint {}",
            path.display()
        )
    })
}

fn preserve_local_conflict_copy(
    root_dir: &Path,
    relative_path: &str,
    local_target: &Path,
) -> Result<()> {
    if !local_target.is_file() {
        return Ok(());
    }

    let timestamp = current_unix_ms();
    let local_backup_dir = conflict_copy_dir(root_dir, "local", relative_path);
    fs::create_dir_all(&local_backup_dir).with_context(|| {
        format!(
            "failed to create conflict backup directory {}",
            local_backup_dir.display()
        )
    })?;
    let file_name = local_target
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "object".to_string());
    let backup_target = local_backup_dir.join(format!("{file_name}.local-conflict-{timestamp}"));

    if fs::rename(local_target, &backup_target).is_err() {
        fs::copy(local_target, &backup_target).with_context(|| {
            format!(
                "failed to copy local file {} to backup {}",
                local_target.display(),
                backup_target.display()
            )
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PathScope;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn validate_user_relative_path_input_normalizes_safe_paths() {
        assert_eq!(
            validate_user_relative_path_input(" /docs\\\\notes.txt ").unwrap(),
            "docs/notes.txt"
        );
    }

    #[test]
    fn validate_user_relative_path_input_rejects_empty_parent_and_colon_segments() {
        assert!(validate_user_relative_path_input("   ").is_err());
        assert!(validate_user_relative_path_input("../notes.txt").is_err());
        assert!(validate_user_relative_path_input("docs/../notes.txt").is_err());
        assert!(validate_user_relative_path_input("docs:file.txt").is_err());
    }

    #[test]
    fn remove_local_path_deletes_files_directories_and_missing_paths() {
        let root = test_root();
        fs::create_dir_all(root.join("nested/dir")).unwrap();
        fs::write(root.join("nested/file.txt"), b"hello").unwrap();
        fs::write(root.join("nested/dir/child.txt"), b"child").unwrap();

        remove_local_path(&root, "nested/file.txt", None, None, None).unwrap();
        remove_local_path(&root, "nested/dir", None, None, None).unwrap();
        remove_local_path(&root, "nested/missing.txt", None, None, None).unwrap();

        assert!(!root.join("nested/file.txt").exists());
        assert!(!root.join("nested/dir").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preserve_local_conflict_copy_moves_file_into_local_conflict_area() {
        let root = test_root();
        let local_target = root.join("docs/report.txt");
        fs::create_dir_all(local_target.parent().unwrap()).unwrap();
        fs::write(&local_target, b"draft").unwrap();

        preserve_local_conflict_copy(&root, "docs/report.txt", &local_target).unwrap();

        assert!(!local_target.exists());
        let backup_dir = conflict_copy_dir(&root, "local", "docs/report.txt");
        let backups = fs::read_dir(&backup_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read(&backups[0]).unwrap(), b"draft");
        assert!(
            backups[0]
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("report.txt.local-conflict-")
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delete_remote_file_skips_empty_local_root_mapping() {
        let scope = PathScope::new(Some("cameras/vm1".to_string()));
        let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:65535");
        delete_remote_file(&client, &scope, "", None, None).unwrap();
    }

    fn test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut root = std::env::temp_dir();
        root.push(format!("ironmesh-conflicts-test-{nonce}"));
        root
    }
}
