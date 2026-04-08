#![cfg(windows)]

use crate::helpers::normalize_path;
use crate::local_state::local_appdata_sync_root_state_dir;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const ACTIVE_HYDRATIONS_DIR: &str = "active-hydrations";
const CANCEL_HYDRATIONS_DIR: &str = "cancel-hydrations";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydrationControlPaths {
    pub normalized_relative_path: String,
    pub active_marker_path: PathBuf,
    pub cancel_marker_path: PathBuf,
}

pub fn hydration_control_paths(
    sync_root_path: &Path,
    relative_path: &str,
) -> HydrationControlPaths {
    let normalized_relative_path = normalize_path(relative_path);
    let marker_name = hydration_marker_name(&normalized_relative_path);
    let state_dir = local_appdata_sync_root_state_dir(sync_root_path);
    HydrationControlPaths {
        normalized_relative_path,
        active_marker_path: state_dir.join(ACTIVE_HYDRATIONS_DIR).join(&marker_name),
        cancel_marker_path: state_dir.join(CANCEL_HYDRATIONS_DIR).join(marker_name),
    }
}

pub fn mark_active_hydration(sync_root_path: &Path, relative_path: &str) -> Result<()> {
    let control = hydration_control_paths(sync_root_path, relative_path);
    write_marker_file(
        &control.active_marker_path,
        &control.normalized_relative_path,
    )
    .with_context(|| {
        format!(
            "failed to mark active hydration for {} under {}",
            control.normalized_relative_path,
            sync_root_path.display()
        )
    })
}

pub fn clear_active_hydration(sync_root_path: &Path, relative_path: &str) -> Result<()> {
    let control = hydration_control_paths(sync_root_path, relative_path);
    remove_marker_file(&control.active_marker_path).with_context(|| {
        format!(
            "failed to clear active hydration marker for {} under {}",
            control.normalized_relative_path,
            sync_root_path.display()
        )
    })
}

pub fn is_active_hydration_marked(sync_root_path: &Path, relative_path: &str) -> bool {
    hydration_control_paths(sync_root_path, relative_path)
        .active_marker_path
        .is_file()
}

pub fn request_hydration_cancel(sync_root_path: &Path, relative_path: &str) -> Result<bool> {
    let control = hydration_control_paths(sync_root_path, relative_path);
    if !control.active_marker_path.is_file() {
        return Ok(false);
    }

    write_marker_file(
        &control.cancel_marker_path,
        &control.normalized_relative_path,
    )
    .with_context(|| {
        format!(
            "failed to request hydration cancel for {} under {}",
            control.normalized_relative_path,
            sync_root_path.display()
        )
    })?;
    Ok(true)
}

pub fn clear_hydration_cancel_request(sync_root_path: &Path, relative_path: &str) -> Result<()> {
    let control = hydration_control_paths(sync_root_path, relative_path);
    remove_marker_file(&control.cancel_marker_path).with_context(|| {
        format!(
            "failed to clear hydration cancel marker for {} under {}",
            control.normalized_relative_path,
            sync_root_path.display()
        )
    })
}

pub fn has_hydration_cancel_request(sync_root_path: &Path, relative_path: &str) -> bool {
    hydration_control_paths(sync_root_path, relative_path)
        .cancel_marker_path
        .is_file()
}

pub fn active_hydration_marker_count(sync_root_path: &Path) -> Result<usize> {
    let state_dir = local_appdata_sync_root_state_dir(sync_root_path).join(ACTIVE_HYDRATIONS_DIR);
    match fs::read_dir(&state_dir) {
        Ok(entries) => Ok(entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_file())
            .count()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => {
            Err(error).with_context(|| format!("failed to enumerate {}", state_dir.display()))
        }
    }
}

fn write_marker_file(path: &Path, normalized_relative_path: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create marker parent {}", parent.display()))?;
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let body = format!("timestamp={timestamp}\npath={normalized_relative_path}\n");
    fs::write(path, body).with_context(|| format!("failed to write marker file {}", path.display()))
}

fn remove_marker_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn hydration_marker_name(relative_path: &str) -> String {
    let normalized_relative_path = normalize_path(relative_path);
    let hash = blake3::hash(normalized_relative_path.as_bytes())
        .to_hex()
        .to_string();
    let windows_relative = normalized_relative_path.replace('/', "\\");
    let leaf = Path::new(&windows_relative)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("hydration");
    let sanitized_leaf = leaf
        .chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() {
                value.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    let label = if sanitized_leaf.is_empty() {
        "hydration".to_string()
    } else {
        sanitized_leaf
    };
    format!("{label}-{hash}.marker")
}

#[cfg(test)]
mod tests {
    use super::{
        clear_active_hydration, clear_hydration_cancel_request, has_hydration_cancel_request,
        hydration_control_paths, is_active_hydration_marked, mark_active_hydration,
        request_hydration_cancel,
    };

    #[test]
    fn cancel_request_requires_active_hydration_marker() {
        let sync_root = std::env::temp_dir().join(format!(
            "ironmesh-hydration-control-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&sync_root).expect("sync root should be created");

        let control = hydration_control_paths(&sync_root, "docs/large.bin");
        let _ = std::fs::remove_file(&control.active_marker_path);
        let _ = std::fs::remove_file(&control.cancel_marker_path);

        assert!(
            !request_hydration_cancel(&sync_root, "docs/large.bin")
                .expect("inactive hydration cancel should not fail"),
            "cancel request should be ignored while no active hydration marker exists"
        );

        mark_active_hydration(&sync_root, "docs/large.bin")
            .expect("active hydration marker should be written");
        assert!(is_active_hydration_marked(&sync_root, "docs/large.bin"));

        assert!(
            request_hydration_cancel(&sync_root, "docs/large.bin")
                .expect("active hydration cancel should succeed"),
            "cancel request should be accepted while hydration is active"
        );
        assert!(has_hydration_cancel_request(&sync_root, "docs/large.bin"));

        clear_hydration_cancel_request(&sync_root, "docs/large.bin")
            .expect("cancel marker should be removed");
        clear_active_hydration(&sync_root, "docs/large.bin")
            .expect("active marker should be removed");
        assert!(!is_active_hydration_marked(&sync_root, "docs/large.bin"));
        assert!(!has_hydration_cancel_request(&sync_root, "docs/large.bin"));

        let _ = std::fs::remove_dir_all(sync_root);
    }
}
