#![cfg(windows)]

use std::path::{Path, PathBuf};

const LOCAL_STATE_ROOT_DIR: &str = "Ironmesh";
const LOCAL_STATE_SYNC_ROOTS_DIR: &str = "sync-roots";
const LOCAL_STATE_CONNECTION_BOOTSTRAP_FILE_NAME: &str = "connection-bootstrap.json";
const LOCAL_STATE_CLIENT_IDENTITY_FILE_NAME: &str = "client-identity.json";

pub(crate) fn local_appdata_sync_root_state_dir(sync_root_path: &Path) -> PathBuf {
    local_appdata_root()
        .join(LOCAL_STATE_SYNC_ROOTS_DIR)
        .join(sync_root_state_label(sync_root_path))
}

pub(crate) fn local_appdata_connection_bootstrap_path(sync_root_path: &Path) -> PathBuf {
    local_appdata_sync_root_state_dir(sync_root_path)
        .join(LOCAL_STATE_CONNECTION_BOOTSTRAP_FILE_NAME)
}

pub(crate) fn local_appdata_client_identity_path(sync_root_path: &Path) -> PathBuf {
    local_appdata_sync_root_state_dir(sync_root_path).join(LOCAL_STATE_CLIENT_IDENTITY_FILE_NAME)
}

fn local_appdata_root() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(LOCAL_STATE_ROOT_DIR)
}

fn sync_root_state_label(sync_root_path: &Path) -> String {
    let normalized = sync_root_path
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    let hash = blake3::hash(normalized.as_bytes()).to_hex().to_string();
    let leaf = sync_root_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("sync-root");
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
        "sync_root".to_string()
    } else {
        sanitized_leaf
    };
    format!("{label}-{hash}")
}

#[cfg(test)]
mod tests {
    use super::{local_appdata_client_identity_path, local_appdata_connection_bootstrap_path};
    use std::path::Path;

    #[test]
    fn local_appdata_state_paths_are_stable_for_sync_root() {
        let sync_root = Path::new(r"C:\Users\Example\IronMesh\Wiz3");
        let bootstrap = local_appdata_connection_bootstrap_path(sync_root);
        let identity = local_appdata_client_identity_path(sync_root);

        assert_eq!(
            bootstrap.file_name().and_then(|value| value.to_str()),
            Some("connection-bootstrap.json")
        );
        assert_eq!(
            identity.file_name().and_then(|value| value.to_str()),
            Some("client-identity.json")
        );
        assert_eq!(bootstrap.parent(), identity.parent());
    }
}
